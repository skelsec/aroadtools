from marshmallow import Schema, fields
from marshmallow_sqlalchemy import ModelConverter, SQLAlchemyAutoSchema

from aroadtools.roadlib.database.metadef.database import User, JSON, Group, DirectoryRole, ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, OAuth2PermissionGrant, AuthorizationPolicy, DirectorySetting, AdministrativeUnit, RoleDefinition


# Model definitions that include a custom JSON type, which doesn't get converted
class RTModelConverter(ModelConverter):
    SQLA_TYPE_MAPPING = dict(
        list(ModelConverter.SQLA_TYPE_MAPPING.items()) +
        [(JSON, fields.Raw)]
    )

# Our custom model schema which uses the model converter from above
class RTModelSchema(SQLAlchemyAutoSchema):
    class Meta:
        model_converter = RTModelConverter

# Schemas for objects
# For each object type there is an <objectname>Schema and <plural objectname>Schema
# the plural version is for lists of objects (doesn't include all fields)
# the regular version includes all possible fields based on the SQLAlchemy meta definition
class UsersSchema(Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'userPrincipalName', 'displayName', 'mail', 'lastDirSyncTime', 'accountEnabled', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'strongAuthenticationDetail', 'userType')

class DevicesSchema(Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'accountEnabled', 'displayName', 'deviceManufacturer', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'deviceId', 'isManaged', 'isRooted', 'dirSyncEnabled')

class DirectoryRoleSchema(Schema):
    class Meta:
        model = DirectoryRole
        fields = ('displayName', 'description')

class OAuth2PermissionGrantsSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = OAuth2PermissionGrant

class AppRoleAssignmentsSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = AppRoleAssignment

class GroupsSchema(Schema):
    class Meta:
        model = Group
        fields = ('displayName', 'description', 'createdDateTime', 'dirSyncEnabled', 'objectId', 'objectType', 'groupTypes', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule')

class AdministrativeUnitsSchema(Schema):
    class Meta:
        model = AdministrativeUnit
        fields = ('displayName', 'description', 'createdDateTime', 'objectId', 'objectType', 'membershipType', 'membershipRule')

class SimpleServicePrincipalsSchema(Schema):
    """
    Simple ServicePrincipalSchema to prevent looping relationships with serviceprincipals
    owning other serviceprincipals
    """
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'servicePrincipalType')

class ServicePrincipalsSchema(Schema):
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'appDisplayName', 'appRoleAssignmentRequired', 'appId', 'appOwnerTenantId', 'publisherName', 'replyUrls', 'appRoles', 'microsoftFirstParty', 'isDirSyncEnabled', 'oauth2Permissions', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals', 'accountEnabled', 'servicePrincipalType')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class ApplicationsSchema(Schema):
    class Meta:
        model = Application
        fields = ('objectId', 'objectType', 'displayName', 'appId', 'appDisplayName', 'oauth2AllowIdTokenImplicitFlow', 'availableToOtherTenants', 'publisherDomain', 'replyUrls', 'appRoles', 'publicClient', 'oauth2AllowImplicitFlow', 'oauth2Permissions', 'homepage', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class DirectoryRolesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = DirectoryRole
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)
    ownedGroups = fields.Nested(GroupsSchema, many=True)

class DeviceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Device
    memberOf = fields.Nested(GroupsSchema, many=True)
    owner = fields.Nested(UsersSchema, many=True)

class GroupSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Group
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)
    memberServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class AdministrativeUnitSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AdministrativeUnit
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)

class ServicePrincipalSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = ServicePrincipal
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberOf = fields.Nested(GroupSchema, many=True)
    oauth2PermissionGrants = fields.Nested(OAuth2PermissionGrantsSchema, many=True)
    appRolesAssigned = fields.Nested(AppRoleAssignmentsSchema, many=True)
    appRolesAssignedTo = fields.Nested(AppRoleAssignmentsSchema, many=True)

class ApplicationSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Application
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)

class TenantDetailSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = TenantDetail

class AuthorizationPolicySchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AuthorizationPolicy

# Instantiate all schemas
user_schema = UserSchema()
device_schema = DeviceSchema()
group_schema = GroupSchema()
application_schema = ApplicationSchema()
td_schema = TenantDetailSchema()
serviceprincipal_schema = ServicePrincipalSchema()
administrativeunit_schema = AdministrativeUnitSchema()
authorizationpolicy_schema = AuthorizationPolicySchema(many=True)
users_schema = UsersSchema(many=True)
devices_schema = DevicesSchema(many=True)
groups_schema = GroupsSchema(many=True)
applications_schema = ApplicationsSchema(many=True)
serviceprincipals_schema = ServicePrincipalsSchema(many=True)
directoryroles_schema = DirectoryRolesSchema(many=True)
administrativeunits_schema = AdministrativeUnitsSchema(many=True)
