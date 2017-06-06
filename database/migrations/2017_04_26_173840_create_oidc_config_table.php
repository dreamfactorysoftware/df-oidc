<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOidcConfigTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create(
            'oidc_config',
            function (Blueprint $t){
                $t->integer('service_id')->unsigned()->primary();
                $t->foreign('service_id')->references('id')->on('service')->onDelete('cascade');
                $t->integer('default_role')->unsigned()->nullable();
                // previously set to 'restrict' which isn't supported by all databases
                // removing the onDelete clause gets the same behavior as No Action and Restrict are defaults.
                $t->foreign('default_role')->references('id')->on('role');
                $t->string('discovery_document')->nullable();
                $t->string('auth_endpoint')->nullable();
                $t->string('token_endpoint')->nullable();
                $t->string('user_endpoint')->nullable();
                $t->boolean('validate_id_token')->default(0);
                $t->string('jwks_uri')->nullable();
                $t->string('scopes')->nullable();
                $t->string('client_id');
                $t->longText('client_secret');
                $t->string('redirect_url');
                $t->string('icon_class')->nullable();
            }
        );
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('oidc_config');
    }
}
