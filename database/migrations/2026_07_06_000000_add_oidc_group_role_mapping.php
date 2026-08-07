<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddOidcGroupRoleMapping extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Add map_group_to_role toggle to oidc_config table
        if (!Schema::hasColumn('oidc_config', 'map_group_to_role')) {
            Schema::table('oidc_config', function (Blueprint $t) {
                $t->boolean('map_group_to_role')->default(0);
            });
        }

        // Add configurable groups claim name (varies by provider: 'groups' for
        // Okta/Keycloak/Azure AD, a namespaced URI for Auth0, etc.)
        if (!Schema::hasColumn('oidc_config', 'groups_claim')) {
            Schema::table('oidc_config', function (Blueprint $t) {
                $t->string('groups_claim')->default('groups');
            });
        }

        // Create role_oidc table for mapping provider groups to DreamFactory roles.
        // group_ref holds a group name OR id depending on the provider - e.g. the
        // group's Object ID (GUID) for Azure AD via OIDC, the group name for Okta.
        if (!Schema::hasTable('role_oidc')) {
            Schema::create('role_oidc', function (Blueprint $t) {
                $t->integer('role_id')->unsigned()->primary();
                $t->foreign('role_id')->references('id')->on('role')->onDelete('cascade');
                $t->string('group_ref', 255);
                $t->index('group_ref');
            });
        }
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('role_oidc');

        if (Schema::hasColumn('oidc_config', 'groups_claim')) {
            Schema::table('oidc_config', function (Blueprint $t) {
                $t->dropColumn('groups_claim');
            });
        }

        if (Schema::hasColumn('oidc_config', 'map_group_to_role')) {
            Schema::table('oidc_config', function (Blueprint $t) {
                $t->dropColumn('map_group_to_role');
            });
        }
    }
}
