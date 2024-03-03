import argparse
import asyncio
import json
import os
import sys
import time
import traceback
import warnings

from aroadtools.roadlib.reqproxy import requestproxy
from aroadtools.roadlib.utils import printhook
import aroadtools.roadlib.database.metadef.database as database
from aroadtools.roadlib.auth import Authentication
from aroadtools.roadlib.database.metadef.database import (
    AdministrativeUnit, Application, ApplicationRef, AppRoleAssignment,
    AuthorizationPolicy, Contact, Device, DirectoryRole, DirectorySetting,
    EligibleRoleAssignment, ExtensionProperty, Group, OAuth2PermissionGrant,
    Policy, RoleAssignment, RoleDefinition, ServicePrincipal, TenantDetail,
    User, lnk_au_member_device, lnk_au_member_group, lnk_au_member_user,
    lnk_device_owner, lnk_group_member_contact, lnk_group_member_device,
    lnk_group_member_group, lnk_group_member_serviceprincipal,
    lnk_group_member_user, lnk_group_owner_serviceprincipal,
    lnk_group_owner_user)
from sqlalchemy import bindparam, func, text
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker

warnings.simplefilter('ignore')

MAX_GROUPS = 3000
MAX_REQ_PER_SEC = 600.0

async def queue_processor(queue):
    while True:
        task = await queue.get()
        # task is already a coroutine, so we wait for it to finish
        await task
        queue.task_done()

class DataDumper(object):
    def __init__(self, token, tenantid = None, api_version = '1.61-internal', engine=None, session=None, dburl = None, skip_first_phase=False, mfa=False, user_agent=None, httpreq=requestproxy, printhook=printhook):
        self.api_version = api_version
        self.tenantid = tenantid
        self.session = session
        self.engine = engine
        self.token = token
        self.tokencounter = 0
        self.tokenfilltime = time.time()
        self.urlcounter = 0
        self.groupcounter = 0
        self.totalgroups = 0
        self.devicecounter = 0
        self.expiretime = None
        self.skip_first_phase = skip_first_phase
        self.mfa = mfa
        self.headers = None
        self.user_agent = user_agent
        self.dburl = dburl
        self.setup_complete = False
        self.httpreq = httpreq
        self.print = printhook

    @staticmethod
    def mknext(url, prevurl):
        if url.startswith('https://'):
            # Absolute URL
            return url + '&api-version=1.61-internal'
        parts = prevurl.split('/')
        if 'directoryObjects' in url:
            return '/'.join(parts[:4]) + '/' + url + '&api-version=1.61-internal'
        return '/'.join(parts[:-1]) + '/' + url + '&api-version=1.61-internal'
    
    def enginecommit(self, dbtype, cache, ignore=False):
        if 'postgresql' in self.dburl and ignore:
            insertst = pginsert(dbtype.__table__)
            statement = insertst.on_conflict_do_nothing(
                index_elements=['objectId']
            )
        elif 'sqlite' in self.dburl and ignore:
            statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
        else:
            statement = dbtype.__table__.insert()
        with self.engine.begin() as conn:
            conn.execute(
                statement,
                cache
            )

    def commit(self, dbtype, cache, ignore=False):
        if 'postgresql' in self.dburl and ignore:
            insertst = pginsert(dbtype.__table__)
            statement = insertst.on_conflict_do_nothing(
                index_elements=['objectId']
            )
        elif 'sqlite' in self.dburl and ignore:
            statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
        else:
            statement = dbtype.__table__.insert()
        self.session.execute(
            statement,
            cache
        )
    
    def commitlink(self, cachedict, ignore=False):
        for linktable, cache in cachedict.items():
            if 'postgresql' in self.dburl and ignore:
                insertst = pginsert(linktable)
                statement = insertst.on_conflict_do_nothing(
                    index_elements=['objectId']
                )
            elif 'sqlite' in self.dburl and ignore:
                statement = linktable.insert().prefix_with('OR IGNORE')
            else:
                statement = linktable.insert()
            # print(cache)
            self.session.execute(
                statement,
                cache
            )
    
    def commitmfa(self, dbtype, cache):
        statement = dbtype.__table__.update().where(dbtype.objectId == bindparam('userid'))
        self.session.execute(
            statement,
            cache
        )
    
    async def checktoken(self):
        if time.time() > self.expiretime - 300:
            auth = Authentication(httpreq=self.httpreq)
            try:
                auth.client_id = self.token['_clientId']
            except KeyError:
                auth.client_id = '1b730954-1685-4b74-9bfd-dac224a7b894'
            auth.tenant = self.token['tenantId']
            auth.tokendata = self.token
            if 'useragent' in self.token:
                auth.set_user_agent(self.token['useragent'])
            if 'refreshToken' in self.token:
                self.token = await auth.authenticate_with_refresh_native(self.token) #originally authenticate_with_refresh but that's not supported :(
                self.headers['Authorization'] = '%s %s' % (self.token['tokenType'], self.token['accessToken'])
                self.expiretime = time.time() + self.token['expiresIn']
                await self.print('Refreshed token')
                return True
            elif time.time() > self.expiretime:
                await self.print('Access token is expired, but no access to refresh token! Dumping will fail')
                return False
        return True
    
    async def ratelimit(self):
        if self.tokencounter < MAX_REQ_PER_SEC:
            now = time.time()
            to_add = MAX_REQ_PER_SEC * (now - self.tokenfilltime)
            self.tokencounter = min(MAX_REQ_PER_SEC, self.tokencounter + to_add)
            self.tokenfilltime = now
        if self.tokencounter < 1:
            # await self.print('Ratelimit reached')
            await asyncio.sleep(0.1)
            await self.ratelimit()
        else:
            self.tokencounter -= 1
    
    async def dumpsingle(self, url, method):
        await self.checktoken()
        await self.ratelimit()
        try:
            self.urlcounter += 1
            res, objects, err = await self.httpreq(url, 'GET', self.headers, restype='json')
            if res.status == 429:
                if self.tokencounter > 0:
                    self.tokencounter -= 10*MAX_REQ_PER_SEC
                    await self.print('Sleeping because of rate-limit hit')
                obj = await self.dumpsingle(url, method)
                return obj
            if res.status != 200:
                # This can happen
                if res.status == 404 and 'applicationRefs' in url:
                    return
                # Ignore default users role not being found
                if res.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                    return
                await self.print('Error %d for URL %s' % (res.status, url))
                return
            return objects
        except Exception as exc:
            traceback.print_exc()
            await self.print(exc)
            return
    
    async def dumphelper(self, url, method=None):
        nexturl = url
        while nexturl:
            await self.checktoken()
            await self.ratelimit()
            try:
                self.urlcounter += 1

                req, objects, err = await self.httpreq(nexturl, 'GET', self.headers, restype='json')
                if err is not None:
                    await self.print('Error during request: %s' % err)
                    return
                # Hold off when rate limit is reached
                if req.status == 429:
                    if self.tokencounter > 0:
                        self.tokencounter -= 10*MAX_REQ_PER_SEC
                        await self.print('Sleeping because of rate-limit hit')
                    continue
                if req.status != 200:
                    # Ignore default users role not being found
                    if req.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                        return
                    await self.print('Error %d for URL %s' % (req.status, nexturl))
                    # print(await req.text())
                    # print(req.headers)
                    await self.print('')
                try:
                    nexturl = DataDumper.mknext(objects['odata.nextLink'], url)
                except KeyError:
                    nexturl = None
                try:
                    for robject in objects['value']:
                        yield robject
                except KeyError:
                    # print(objects)
                    pass
            except Exception as exc:
                traceback.print_exc()
                await self.print(exc)
                return

    async def dump_object(self, objecttype, dbtype, method=None):
        #if method is None:
        #    method = None
        url = 'https://graph.windows.net/%s/%s?api-version=1.61-internal' % (self.tenantid, objecttype)
        cache = []
        async for obj in self.dumphelper(url, method=method):
            cache.append(obj)
            if len(cache) > 1000:
                self.enginecommit(dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            self.enginecommit(dbtype, cache)

    async def dump_l_to_db(self, url, method, mapping, linkname, childtbl, parent):
        i = 0
        async for obj in self.dumphelper(url, method=method):
            objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    childtbl, linkname = mapping[objclass]
                except KeyError:
                    await self.print('Unsupported member type: %s for parent %s' % (objclass, parent.__table__))
                    continue
            child = self.session.get(childtbl, objectid)
            if not child:
                try:
                    parentname = parent.displayName
                except AttributeError:
                    parentname = parent.objectId
                await self.print('Non-existing child found on %s %s: %s' % (parent.__table__, parentname, objectid))
                continue
            getattr(parent, linkname).append(child)
            i += 1
            if i > 1000:
                self.session.commit()
                i = 0
        if str(parent.__table__) == 'Groups':
            self.groupcounter += 1
            await self.print('Done processing {0}/{1} groups'.format(int(self.groupcounter/2), self.totalgroups))

    async def dump_l_to_linktable(self, url, method, mapping, parentid, objecttype):
        i = 0
        cache = {}
        async for obj in self.dumphelper(url, method=method):
            objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    linktable, leftcol, rightcol = mapping[objclass]
                except KeyError:
                    await self.print('Unsupported member type: %s for parent %s' % (objclass, objecttype))
                    continue
            try:
                cache[linktable].append({leftcol: parentid, rightcol: objectid})
            except KeyError:
                cache[linktable] = [{leftcol: parentid, rightcol: objectid}]
            i += 1
            if i > 1000:
                self.commitlink(cache)
                cache = {}
                i = 0
        self.commitlink(cache)
        if str(objecttype) == 'groups':
            self.groupcounter += 1
            await self.print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(self.groupcounter/2), self.totalgroups, self.devicecounter, self.totaldevices))
        if str(objecttype) == 'devices':
            self.devicecounter += 1
            await self.print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(self.groupcounter/2), self.totalgroups, self.devicecounter, self.totaldevices))

    async def dump_links(self, objecttype, linktype, parenttbl, mapping=None, linkname=None, childtbl=None, method=None):
        parents = self.session.query(parenttbl).all()
        jobs = []
        i = 0
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s/$links/%s?api-version=%s' % (self.tenantid, objecttype, parent.objectId, linktype, self.api_version)
            jobs.append(self.dump_l_to_db(url, method, mapping, linkname, childtbl, parent))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                i = 0
        await asyncio.gather(*jobs)
        self.session.commit()

    async def dump_links_with_queue(self, queue, objecttype, linktype, parenttbl, mapping=None, method=None):
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        for parentid, in parents:
            url = 'https://graph.windows.net/%s/%s/%s/$links/%s?api-version=%s' % (self.tenantid, objecttype, parentid, linktype, self.api_version)
            # Chunk it to avoid huge memory usage
            await queue.put(self.dump_l_to_linktable(url, method, mapping, parentid, objecttype))
        await queue.join()
        self.session.commit()

    async def dump_mfa_to_db(self, url, parentid, cache, method=None):
        obj = await self.dumpsingle(url, method=method)
        if not obj:
            return
        cache.append({'userid':parentid,'strongAuthenticationDetail':obj['strongAuthenticationDetail']})

    async def dump_mfa(self, objecttype, parenttbl, method=None):
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        cache = []
        i = 0
        for parentid, in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s&$select=strongAuthenticationDetail,objectId' % (self.tenantid, objecttype, parentid, self.api_version)
            jobs.append(self.dump_mfa_to_db(url, method, parentid, cache))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                self.commitmfa(parenttbl, cache)
                del cache[:]
                i = 0
        await asyncio.gather(*jobs)
        self.commitmfa(parenttbl, cache)
        del cache[:]

    async def dump_lo_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for multiple linked objects (returned as a list)
        """
        async for obj in self.dumphelper(url, method=method):
            # objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            # await self.print(parent.objectId, obj)
            cache.append(obj)
            if len(cache) > 1000:
                self.commit(linkobjecttype, cache, ignore=ignore_duplicates)
                del cache[:]

    async def dump_so_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for objects that are returned as single objects (direct values)
        """
        obj = await self.dumpsingle(url, method=method)
        if not obj:
            return
        cache.append(obj)
        if len(cache) > 1000:
            self.commit(linkobjecttype, cache, ignore=ignore_duplicates)
            del cache[:]

    async def dump_linked_objects(self, objecttype, linktype, parenttbl, linkobjecttype, method=None, ignore_duplicates=False):
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s/%s?api-version=%s' % (self.tenantid, objecttype, parent.objectId, linktype, self.api_version)
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            self.commit(linkobjecttype, cache, ignore=ignore_duplicates)
        self.session.commit()


    async def dump_object_expansion(self, objecttype, dbtype, expandprop, linkname, childtbl, mapping=None, method=None):
        url = 'https://graph.windows.net/%s/%s?api-version=%s&$expand=%s' % (self.tenantid, objecttype, self.api_version, expandprop)
        i = 0
        async for obj in self.dumphelper(url, method=method):
            if len(obj[expandprop]) > 0:
                parent = self.session.get(dbtype, obj['objectId'])
                if not parent:
                    await self.print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, expandprop, obj['objectId']))
                    continue
                for epdata in obj[expandprop]:
                    objclass = epdata['odata.type']
                    if mapping is not None:
                        try:
                            childtbl, linkname = mapping[objclass]
                        except KeyError:
                            await self.print('Unsupported member type: %s' % objclass)
                            continue
                    child = self.session.get(childtbl, epdata['objectId'])
                    if not child:
                        await self.print('Non-existing child during expansion %s %s: %s' % (dbtype.__table__, expandprop, epdata['objectId']))
                        continue
                    getattr(parent, linkname).append(child)
                    i += 1
                    if i > 1000:
                        self.session.commit()
                        i = 0
        self.session.commit()

    async def dump_keycredentials(self, objecttype, dbtype, method=None):
        cache = []
        url = 'https://graph.windows.net/%s/%s?api-version=1.61-internal&$select=keyCredentials,objectId' % (self.tenantid, objecttype)
        async for obj in self.dumphelper(url, method=method):
            cache.append({'userid':obj['objectId'], 'keyCredentials':obj['keyCredentials']})
            if len(cache) > 1000:
                self.commitmfa(dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            self.commitmfa(dbtype, cache)
        del cache[:]

    async def dump_apps_from_list(self, parents, endpoint, dbtype, ignore_duplicates=True):
        cache = []
        jobs = []
        for parentid in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s' % (self.tenantid, endpoint, parentid, self.api_version)
            jobs.append(self.dump_so_to_db(url, None, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            self.commit(dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_each(self, parenttbl, endpoint, dbtype, ignore_duplicates=True):
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s' % (self.tenantid, endpoint, parent.appId, self.api_version)
            jobs.append(self.dump_so_to_db(url, None, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            self.commit(dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_custom_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/roleAssignments?api-version=%s&$filter=roleDefinitionId eq \'%s\'' % (self.tenantid, self.api_version, parent.objectId)
            jobs.append(self.dump_lo_to_db(url, None, dbtype, cache))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            self.commit(dbtype, cache)
        self.session.commit()

    async def dump_eligible_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/eligibleRoleAssignments?api-version=%s&$filter=roleDefinitionId eq \'%s\'' % (self.tenantid, self.api_version, parent.objectId)
            jobs.append(self.dump_lo_to_db(url, None, dbtype, cache))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            self.commit(dbtype, cache)
        self.session.commit()
    
    async def setup(self):
        if 'tenantId' in self.token:
            # token overrides tenantid
            self.tenantid = self.token['tenantId']
        if self.tenantid is None:
            self.tenantid = 'myorganization'
        
        self.expiretime = time.mktime(time.strptime(self.token['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
        self.headers = {
            'Authorization': '%s %s' % (self.token['tokenType'], self.token['accessToken'])
        }
        
        auth = Authentication(httpreq = self.httpreq)
        if self.user_agent is not None:
            self.headers['User-Agent'] = self.user_agent
            auth.set_user_agent(self.user_agent)
            # Store this in the token as well
            self.token['useragent'] = auth.user_agent
        
        tokres = await self.checktoken()
        if not tokres:
            raise Exception('Token is expired and no refresh token is available')
        
        await self.setup_db()
        self.setup_complete = True
    
    async def setup_db(self):
        # a bit annying to set this up but I've been there before
        # if you specified more than one of these, you're on your own
        
        if self.skip_first_phase:
            destroy_db = False
        else:
            destroy_db = True
        
        # if we have engine then use that
        if self.engine is None:
            if self.session is None:
                if self.dburl is None:
                    raise Exception('No database information specified! Please specify either an engine or a dburl or a session')
                # we only have dburl
                self.engine = database.init(destroy_db, dburl=self.dburl)
                sm = sessionmaker(bind=self.engine)
                self.session = sm()
            else:
                # we only have session, get engine from that
                self.engine = self.session.get_bind()
        else:
            if self.session is None:
                # we have engine, but no session. Let's make one
                sm = sessionmaker(bind=self.engine)
                self.session = sm()

    async def run(self):
        start_time = time.time()
        
        if not self.setup_complete:
            await self.setup()

        if not self.skip_first_phase:
            await self.print('Starting data gathering phase 1 of 2 (collecting objects)')
            #dumper.ahsession = ahsession
            tasks = []
            tasks.append(self.dump_object('users', User))
            tasks.append(self.dump_object('tenantDetails', TenantDetail))
            tasks.append(self.dump_object('policies', Policy))
            tasks.append(self.dump_object('servicePrincipals', ServicePrincipal))
            tasks.append(self.dump_object('groups', Group))
            tasks.append(self.dump_object('administrativeUnits', AdministrativeUnit))
            tasks.append(self.dump_object('applications', Application))
            tasks.append(self.dump_object('devices', Device))
            # tasks.append(self.dump_object('domains', Domain))
            tasks.append(self.dump_object('directoryRoles', DirectoryRole))
            tasks.append(self.dump_object('roleDefinitions', RoleDefinition))
            # tasks.append(self.dump_object('roleAssignments', RoleAssignment))
            tasks.append(self.dump_object('contacts', Contact))
            # tasks.append(self.dump_object('getAvailableExtensionProperties', ExtensionProperty, method=ahsession.post))
            tasks.append(self.dump_object('oauth2PermissionGrants', OAuth2PermissionGrant))
            tasks.append(self.dump_object('authorizationPolicy', AuthorizationPolicy))
            tasks.append(self.dump_object('settings', DirectorySetting))
            await asyncio.gather(*tasks)
        
        else:
            # Delete existing links to make sure we start with clean data
            for table in database.Base.metadata.tables.keys():
                if table.startswith('lnk_'):
                    self.session.execute(text("DELETE FROM {0}".format(table)))
            self.session.query(ApplicationRef).delete()
            self.session.query(RoleAssignment).delete()
            self.session.query(EligibleRoleAssignment).delete()
            self.session.commit()
        
        # Mapping object, mapping type returned to Table and link name
        group_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
            'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
            'Microsoft.DirectoryServices.Contact': (Contact, 'memberContacts'),
            'Microsoft.DirectoryServices.Device': (Device, 'memberDevices'),
            'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
        }
        group_owner_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'ownerUsers'),
            'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'ownerServicePrincipals'),
        }
        owner_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'ownerUsers'),
            'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'ownerServicePrincipals'),
        }
        au_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
            'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
            'Microsoft.DirectoryServices.Device': (Device, 'memberDevices'),
        }
        role_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
            'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
            'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
        }
        # Direct link mapping
        group_link_mapping = {
            'Microsoft.DirectoryServices.User': (lnk_group_member_user, 'Group', 'User'),
            'Microsoft.DirectoryServices.Group': (lnk_group_member_group, 'Group', 'childGroup'),
            'Microsoft.DirectoryServices.Contact': (lnk_group_member_contact, 'Group', 'Contact'),
            'Microsoft.DirectoryServices.Device': (lnk_group_member_device, 'Group', 'Device'),
            'Microsoft.DirectoryServices.ServicePrincipal': (lnk_group_member_serviceprincipal, 'Group', 'ServicePrincipal'),
        }
        au_link_mapping = {
            'Microsoft.DirectoryServices.User': (lnk_au_member_user, 'AdministrativeUnit', 'User'),
            'Microsoft.DirectoryServices.Group': (lnk_au_member_group, 'AdministrativeUnit', 'Group'),
            'Microsoft.DirectoryServices.Device': (lnk_au_member_device, 'AdministrativeUnit', 'Device'),
        }
        group_owner_link_mapping = {
            'Microsoft.DirectoryServices.User': (lnk_group_owner_user, 'Group', 'User'),
            'Microsoft.DirectoryServices.ServicePrincipal': (lnk_group_owner_serviceprincipal, 'Group', 'ServicePrincipal'),
        }
        device_link_mapping = {
            'Microsoft.DirectoryServices.User': (lnk_device_owner, 'Device', 'User'),
        }


        self.totalgroups = self.session.query(func.count(Group.objectId)).scalar()
        self.totaldevices = self.session.query(func.count(Device.objectId)).scalar()
        if self.totalgroups > MAX_GROUPS:
            await self.print('Gathered {0} groups, switching to 3-phase approach for efficiency'.format(self.totalgroups))
        
        if self.totalgroups > MAX_GROUPS:
            await self.print('Starting data gathering phase 2 of 3 (collecting properties and relationships)')
        else:
            await self.print('Starting data gathering phase 2 of 2 (collecting properties and relationships)')

        tasks = []
        if self.totalgroups <= MAX_GROUPS:
            tasks.append(self.dump_links('groups', 'members', Group, mapping=group_mapping))
            tasks.append(self.dump_links('groups', 'owners', Group, mapping=group_owner_mapping))
            tasks.append(self.dump_links('administrativeUnits', 'members', AdministrativeUnit, mapping=au_mapping))
            tasks.append(self.dump_object_expansion('devices', Device, 'registeredOwners', 'owner', User))
        tasks.append(self.dump_links('directoryRoles', 'members', DirectoryRole, mapping=role_mapping))
        tasks.append(self.dump_linked_objects('servicePrincipals', 'appRoleAssignedTo', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(self.dump_linked_objects('servicePrincipals', 'appRoleAssignments', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(self.dump_object_expansion('servicePrincipals', ServicePrincipal, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(self.dump_object_expansion('applications', Application, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(self.dump_custom_role_members(RoleAssignment))
        tasks.append(self.dump_eligible_role_members(EligibleRoleAssignment))
        if self.mfa:
            tasks.append(self.dump_mfa('users', User))
        tasks.append(self.dump_each(ServicePrincipal, 'applicationRefs', ApplicationRef))
        tasks.append(self.dump_keycredentials('servicePrincipals', ServicePrincipal))
        tasks.append(self.dump_keycredentials('applications', Application))
        await asyncio.gather(*tasks)
        self.session.commit()


        tasks = []
        if self.totalgroups > MAX_GROUPS:
            await self.print('Starting data gathering phase 3 of 3 (collecting group memberships and device owners)')
            queue = asyncio.Queue(maxsize=100)
            # Start the workers
            workers = []
            for i in range(100):
                workers.append(asyncio.ensure_future(queue_processor(queue)))
            tasks.append(self.dump_links_with_queue(queue, 'devices', 'registeredOwners', Device, mapping=device_link_mapping))
            tasks.append(self.dump_links_with_queue(queue, 'groups', 'members', Group, mapping=group_link_mapping))
            tasks.append(self.dump_links_with_queue(queue, 'groups', 'owners', Group, mapping=group_owner_link_mapping))
            tasks.append(self.dump_links_with_queue(queue, 'administrativeUnits', 'members', AdministrativeUnit, mapping=au_link_mapping))
            await asyncio.gather(*tasks)
            await queue.join()
            for worker_task in workers:
                worker_task.cancel()

        self.session.commit()
        self.session.close()

        elapsed_time = time.time() - start_time
        await self.print('Data gathering completed in {0:0.2f} seconds'.format(elapsed_time))

    @staticmethod
    def getargs(gather_parser):
        gather_parser.add_argument('-d',
                                '--database',
                                action='store',
                                help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools. Default: roadrecon.db',
                                default='roadrecon.db')
        gather_parser.add_argument('-f',
                                '--tokenfile',
                                action='store',
                                help='File to read credentials from obtained by roadrecon auth',
                                default='.roadtools_auth')
        gather_parser.add_argument('--tokens-stdin',
                                action='store_true',
                                help='Read tokens from stdin instead of from disk')
        gather_parser.add_argument('--mfa',
                                action='store_true',
                                help='Dump MFA details (requires use of a privileged account)')
        gather_parser.add_argument('--skip-first-phase',
                                action='store_true',
                                help='Skip the first phase (assumes this has been previously completed)')
        gather_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID to gather, if this info is not stored in the token')
        gather_parser.add_argument('-ua', '--user-agent', action='store',
                                    help='Custom user agent to use. By default aiohttp default user agent is used, and python-requests is used for token renewal')

async def amain():
    parser = argparse.ArgumentParser(add_help=True, description='ROADrecon - Gather Azure AD information', formatter_class=argparse.RawDescriptionHelpFormatter)
    DataDumper.getargs(parser)
    args = parser.parse_args()
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    if args.tokens_stdin:
        token = json.loads(sys.stdin.read())
    else:
        with open(args.tokenfile, 'r') as infile:
            token = json.load(infile)
    if not ':/' in args.database:
        if args.database[0] != '/':
            dburl = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            dburl = 'sqlite:///' + args.database
    else:
        dburl = args.database

    dumper = DataDumper(token, tenantid=args.tenant, dburl = dburl, user_agent=args.user_agent, mfa=args.mfa, skip_first_phase=args.skip_first_phase)
    await dumper.run()

def main():
    asyncio.run(amain())

if __name__ == "__main__":
    main()
