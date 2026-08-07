<?php

namespace DreamFactory\Core\Oidc\Models;

use DreamFactory\Core\Models\BaseModel;
use DreamFactory\Core\Models\Role;

/**
 * RoleOidc
 *
 * Maps an OpenID Connect provider group (by name or id) to a DreamFactory role.
 *
 * @property integer $role_id
 * @property string  $group_ref
 * @method static \Illuminate\Database\Query\Builder|RoleOidc whereRoleId($value)
 * @method static \Illuminate\Database\Query\Builder|RoleOidc whereGroupRef($value)
 */
class RoleOidc extends BaseModel
{
    /** @type string */
    protected $table = 'role_oidc';

    /** @type string */
    protected $primaryKey = 'role_id';

    /** @type array */
    protected $fillable = ['role_id', 'group_ref'];

    /** @type bool */
    public $timestamps = false;

    /** @type bool */
    public $incrementing = false;

    /**
     * Get the config schema for group role mapping.
     *
     * @return array
     */
    public static function getConfigSchema()
    {
        $roles = Role::whereIsActive(1)->get();
        $roleList = [];

        foreach ($roles as $role) {
            $roleList[] = [
                'label' => $role->name,
                'name'  => $role->id,
            ];
        }

        return [
            [
                'name'        => 'role_id',
                'label'       => 'Role',
                'type'        => 'picklist',
                'required'    => true,
                'values'      => $roleList,
                'description' => 'Select the DreamFactory role to assign.',
            ],
            [
                'name'        => 'group_ref',
                'label'       => 'Group Name or ID',
                'type'        => 'string',
                'required'    => true,
                'description' => 'The group value emitted in the provider\'s groups claim. ' .
                                 'For Azure AD via OIDC use the group\'s Object ID (GUID); ' .
                                 'for Okta/Keycloak use the group name.',
            ],
        ];
    }
}
