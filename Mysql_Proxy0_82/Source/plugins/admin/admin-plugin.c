/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2009, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */

/**
 * @page page-plugin-admin Administration plugin
 *
 * The admin plugin exposes the internals of the MySQL Proxy on a SQL interface 
 * to the outside world. 
 *
 * @section plugin-admin-options Configuration
 *
 * @li @c --admin-address    defaults to @c :4041
 * @li @c --admin-lua-script specifies the lua script to load that exposes handles the SQL statements
 * @li @c --admin-username   username
 * @li @c --admin-password   password
 *
 * @section plugin-admin-implementation Implementation
 *
 * The admin plugin handles two SQL queries by default that are used by the mysql commandline client when
 * it logins to expose the version string and username. All other queries are returned with an error if they 
 * are not handled by the Lua script (@c --admin-lua-script). 
 *
 * The script provides a @c read_query() function which returns a result-set in the same way as the proxy
 * module does:
 *
 * @include lib/admin.lua
 *
 * @section plugin-admin-missing To fix before 1.0
 *
 * Before MySQL Proxy 1.0 we have to cleanup the admin plugin to:
 *
 * @li replace the hard-coded username, password by a real credential store @see network_mysqld_admin_plugin_apply_config()
 * @li provide a full fleged admin script that exposes all the internal stats @see lib/admin.lua
 *
 * @section plugin-admin-backends Backends 
 *
 * @b TODO The admin plugin should also be able to change and add the information about the backends
 * while the MySQL Proxy is running. It is stored in the @c proxy.global.backends table can be mapped to SQL commands.
 *
 * @li support for @c SHOW @c CREATE @c TABLE should return @code
 *   CREATE TABLE backends {
 *     id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
 *     address VARCHAR(...) NOT NULL,
 *     port INT,
 *     is_enabled INT NOT NULL, -- 0 or 1, a bool
 *   }
 * @endcode
 * @li getting all backends @code
 *   SELECT * FROM backends;
 *   SELECT * FROM backends WHERE id = 1;
 * @endcode
 * @li disable backends (a flag needs to be added to the backend code) @code
 *   UPDATE backends SET is_enabled = 0;
 * @endcode
 * @li adding and removing backends like @code
 *   INSERT INTO backends ( address, port ) VALUES ( "10.0.0.20", 3306 );
 *   DELETE backends WHERE id = 1;
 * @endcode
 *
 * In a similar way the @c config section of @c proxy.global should be exposed allowing the admin plugin to change the
 * configuration at runtime. @see lib/proxy/auto-config.lua
 */
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <errno.h>

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "network-mysqld-lua.h"

#include "sys-pedantic.h"
#include "glib-ext.h"
#include "lua-env.h"
#include "chassis-gtimeval.h"
#include "chassis-event-thread.h"

#include <gmodule.h>

#define C(x) x, sizeof(x) -1
#define S(x) x->str, x->len

struct chassis_plugin_config {
	gchar *address;                   /**< listening address of the admin interface */

	gchar *lua_script;                /**< script to load at the start the connection */

	gchar *admin_username;            /**< login username */
	gchar *admin_password;            /**< login password */
    gchar *users_file;                /**< white list file */

	network_mysqld_con *listen_con;
};

int network_mysqld_con_handle_stmt(chassis G_GNUC_UNUSED *chas, network_mysqld_con *con, GString *s) {
	gsize i, j;
	GPtrArray *fields;
	GPtrArray *rows;
	GPtrArray *row;

	
	switch(s->str[NET_HEADER_SIZE]) {
	case COM_QUERY:
		fields = NULL;
		rows = NULL;
		row = NULL;

		if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select @@version_comment limit 1"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fielddefs_new();

			field = network_mysqld_proto_fielddef_new();
			field->name = g_strdup("@@version_comment");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("MySQL Enterprise Agent"));
			g_ptr_array_add(rows, row);

			network_mysqld_con_send_resultset(con->client, fields, rows);
			
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select USER()"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fielddefs_new();
			field = network_mysqld_proto_fielddef_new();
			field->name = g_strdup("USER()");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("root"));
			g_ptr_array_add(rows, row);

			network_mysqld_con_send_resultset(con->client, fields, rows);
		} else {
			network_mysqld_con_send_error(con->client, C("(admin-server) query not known"));
		}

		/* clean up */
		if (fields) {
			network_mysqld_proto_fielddefs_free(fields);
			fields = NULL;
		}

		if (rows) {
			for (i = 0; i < rows->len; i++) {
				row = rows->pdata[i];

				for (j = 0; j < row->len; j++) {
					g_free(row->pdata[j]);
				}

				g_ptr_array_free(row, TRUE);
			}
			g_ptr_array_free(rows, TRUE);
			rows = NULL;
		}

		break;
	case COM_QUIT:
		break;
	case COM_INIT_DB:
		network_mysqld_con_send_ok(con->client);
		break;
	default:
		network_mysqld_con_send_error(con->client, C("unknown COM_*"));
		break;
	}

	return 0;
}

NETWORK_MYSQLD_PLUGIN_PROTO(server_con_init) {
	network_mysqld_auth_challenge *challenge;
	GString *packet;

	challenge = network_mysqld_auth_challenge_new();
	challenge->server_version_str = g_strdup("5.0.99-agent-admin");
	challenge->server_version     = 50099;
	challenge->charset            = 0x08; /* latin1 */
	challenge->capabilities       = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD;
	challenge->server_status      = SERVER_STATUS_AUTOCOMMIT;
	challenge->thread_id          = 1;

	network_mysqld_auth_challenge_set_challenge(challenge); /* generate a random challenge */

	packet = g_string_new(NULL);
	network_mysqld_proto_append_auth_challenge(packet, challenge);
	con->client->challenge = challenge;

	network_mysqld_queue_append(con->client, con->client->send_queue, S(packet));

	g_string_free(packet, TRUE);
	
	con->state = CON_STATE_SEND_HANDSHAKE;

	g_assert(con->plugin_con_state == NULL);

	con->plugin_con_state = network_mysqld_con_lua_new();

	return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(server_read_auth) {
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_auth_response *auth;
	GString *excepted_response;
	GString *hashed_password;
	
	recv_sock = con->client;
	send_sock = con->client;

	packet.data = g_queue_peek_head(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	/* decode the packet */
	network_mysqld_proto_skip_network_header(&packet);

	auth = network_mysqld_auth_response_new();
	if (network_mysqld_proto_get_auth_response(&packet, auth)) {
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	if (!(auth->capabilities & CLIENT_PROTOCOL_41)) {
		/* should use packet-id 0 */
		network_mysqld_queue_append(con->client, con->client->send_queue, C("\xff\xd7\x07" "4.0 protocol is not supported"));
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	
	con->client->response = auth;
	
	/* check if the password matches */
	excepted_response = g_string_new(NULL);
	hashed_password = g_string_new(NULL);

	if (!strleq(S(con->client->response->username), con->config->admin_username, strlen(con->config->admin_username))) {
		network_mysqld_con_send_error_full(send_sock, C("unknown user"), 1045, "28000");
		
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (network_mysqld_proto_password_hash(hashed_password, con->config->admin_password, strlen(con->config->admin_password))) {
	} else if (network_mysqld_proto_password_scramble(excepted_response,
				S(recv_sock->challenge->challenge),
				S(hashed_password))) {
		network_mysqld_con_send_error_full(send_sock, C("scrambling failed"), 1045, "28000");
		
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (!g_string_equal(excepted_response, auth->response)) {
		network_mysqld_con_send_error_full(send_sock, C("password doesn't match"), 1045, "28000");
		
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else {
		network_mysqld_con_send_ok(send_sock);
	
		con->state = CON_STATE_SEND_AUTH_RESULT;
	}

	g_string_free(hashed_password, TRUE);	
	g_string_free(excepted_response, TRUE);

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
	

	return NETWORK_SOCKET_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
/* add by vinchen/CFR */

//same with proxy-plugin's chassis_plugin_config
// struct chassis_proxy_plugin_config {
// 	gchar *address;                   /**< listening address of the proxy */
// 
// 	gchar **backend_addresses;        /**< read-write backends */
// 	gchar **read_only_backend_addresses; /**< read-only  backends */
// 
// 	gint fix_bug_25371;               /**< suppress the second ERR packet of bug #25371 */
// 
// 	gint profiling;                   /**< skips the execution of the read_query() function */
// 	
// 	gchar *lua_script;                /**< script to load at the start the connection */
// 
// 	gint pool_change_user;            /**< don't reset the connection, when a connection is taken from the pool
// 					       - this safes a round-trip, but we also don't cleanup the connection
// 					       - another name could be "fast-pool-connect", but that's too friendly
// 					       */
// 
// 	gint start_proxy;
// 
// 	network_mysqld_con*		listen_con;
// };

gchar*		ini_str_header = 
"[mysql-proxy]\n\
#* mean that you should always set the parameter\n\
\n";

gchar*		ini_str_admin = 
"########Admin Options#########\n\
%sadmin-address=%s\n\
    #*The admin module listening host and port(Default:0.0.0.0:4041)\n\
%sadmin-username=%s\n\
    #*Authentication user name for admin module\n\
%sadmin-password=%s\n\
    #*Authentication password for admin module\n\
%sadmin-lua-script=%s\n\
    #*Script to execute by the admin module\n\
%sadmin-users-file=%s\n\
    #*White list file of user@ip\n\
\n";

// gchar*		ini_str_proxy1 = 
// "#########Proxy Options#########\n\
// %sproxy-address=%s\n\
//     #*The listening proxy server host and port(P for short)\n\
// %sproxy-backend-addresses=%s\n\
//     #*The MySQL server host and port(b for short)\n\
// %sproxy-read-only-backend-addresses=%s\n\
//     #The MySQL server host and port (read only)\n\
// %sproxy-lua-script=%s\n\
//     #Filename for Lua script for proxy operations\n";
// 
// gchar*		ini_str_proxy2 =
// "%sproxy-fix-bug-25371 = true\n\
//     #Enable the fix bug #25371 (mysqld > 5.1.12) for older libmysql versions\n\
// %sproxy-pool-no-change-user = false\n\
//     #Do not use the protocol CHANGE_USER command to reset the connection when coming from the connection pool\n\
// %sproxy-skip-profiling = false\n\
//     #Disable query profiling\n\
// %sno-proxy = false\n\
//     #Do not start the proxy module\n\
// \n";

gchar*		ini_str_app1 = 
"#########Applications Options#########\n\
%sbasedir=%s\n\
    #The base directory prefix for paths in the configuration(Default: dir of Mysql-proxy executable file, or should be absolute path)\n\
%sevent-threads = %d\n\
    #*The number of event-handling threads(Default 1, prefer to prime number)\n\
%slog-file=%s\n\
    #*The file where error messages are logged\n\
%slog-level=%s\n\
    #*The logging level(Should be error, critical, warning, info, message, debug, Default critical)\n\
%splugins=%s\n\
    #*List of plugins to load\n\
%skeepalive = true\n\
    #*Try to restart the proxy if a crash occurs\n\
%sdaemon = true\n\
    #*Start in daemon mode\n\
%sconn_log = %s\n\
	#*Record user login log\n\
%signore-user = %s\n\
	#*The user not record to login log\n";

gchar*		ini_str_app2 =
"%smax-open-files=%d\n\
    #The maximum number of open files to support(Default 0, limit by OS)\n\
%slua-cpath=%s\n\
    #Set the LUA_CPATH\n\
%slua-path=%s\n\
    #Set the LUA_PATH   \n\
%slog-back-trace-on-crash = true\n\
    #*Try to invoke the debugger and generate a backtrace on crash\n\
%slog-use-syslog = true\n\
    #Log errors to syslog  \n\
%spid-file=%s\n\
    #File in which to store the process ID\n\
%splugin-dir=%s\n\
    #Directory containing plugin files\n\
%suser=%s\n\
    #The user to use when running mysql-proxy\n";

#define EC_ADMIN_SUCCESS	0
#define EC_ADMIN_UNKNOWN    1	
#define EC_ADMIN_REFRESH_BACKENDS_FAIL              2	
#define EC_ADMIN_REFRESH_NO_CONS_FILE      3   
#define EC_ADMIN_REFRESH_WIRTE_FILE_FAIL   4	
#define EC_ADMIN_REFRESH_USERS_FAIL                 5	
#define EC_ADMIN_REFRESH_USERS_NO_CONS_FILE         6   
#define EC_ADMIN_REFRESH_USERS_WIRTE_FILE_FAIL      7	
#define EC_ADMIN_FAIL       8	
#define EC_ADMIN_REFRESH_CONNLOG_FAIL                 9	

void
network_mysqld_admin_plugin_get_ini_str(
	gchar*				    buf,
    guint                   buf_len,
    chassis_plugin_config*  config,
    chassis*                srv
)
{
	sprintf(buf, ini_str_admin, 
		config->address ? "" : "#",         config->address ? config->address : "0.0.0.0:4041",
		config->admin_username ? "" : "#",  config->admin_username ? config->admin_username : "proxy",
		config->admin_password ? "" : "#",  config->admin_password ? config->admin_password : "proxy",
		config->lua_script ? "" : "#",      config->lua_script ? config->lua_script : "admin.lua",
		config->users_file ? "" : "#", config->users_file ? config->users_file: "proxy-user.cnf");
}


int		
admin_configure_flush_to_file(
	chassis*			srv							  
)
{
	GString*			new_str = NULL;
	GString*			backends_str = NULL;
	GString*			r_backends_str = NULL;
// 	gint				backends_cnt = 0;
// 	gint				r_backends_cnt = 0;
	gchar				buf[65535];
	gchar				plugins_buf[1000];
	GString*			ignore_str;
	guint				i;
	chassis_plugin*		plugin;
	chassis_plugin*		admin_plugin = NULL;
	chassis_plugin*		proxy_plugin = NULL;
//	network_backend_t*	backend = NULL;
//	struct chassis_proxy_plugin_config*		proxy_config;
	FILE*				ini_file = NULL;
	int					ret;

	if (!srv->default_file)
		return EC_ADMIN_REFRESH_NO_CONS_FILE;

	new_str = g_string_new_len(NULL, 100000);

	g_string_append(new_str, ini_str_header);

	g_assert(srv->modules->len <= 2);
	
	//find plugins
	for (i = 0; i < srv->modules->len; ++i)
	{
		plugin = g_ptr_array_index(srv->modules, i);

		if (strcmp(plugin->name, "admin") == 0)
			admin_plugin = plugin;
		else if (strcmp(plugin->name, "proxy") == 0)
			proxy_plugin = plugin;
		else
			g_assert(0);

		if (i == 0)
			strcpy(plugins_buf, plugin->name);
		else
		{
			strcat(plugins_buf, ", ");
			strcat(plugins_buf, plugin->name);
		}
	}
    
	ignore_str = g_string_new_len(NULL,100);
	for (i = 0; srv->ignore_user && srv->ignore_user[i]; i++){
		if (i > 0){
			g_string_append(ignore_str,",");
		}
		g_string_append(ignore_str, srv->ignore_user[i]);
	}

	//find_backends
// 	for (i = 0; i < srv->priv->backends->backends->len; ++i)
// 	{
// 		backend = g_ptr_array_index(srv->priv->backends->backends, i);
// 		if (backend->type == BACKEND_TYPE_RW)
// 		{
// 			if (backends_cnt++ == 0)
// 			{
// 				backends_str = g_string_new_len(NULL, 100);
// 				g_string_append(backends_str, backend->addr->name->str);
// 			}
// 			else
// 			{
// 				g_assert(backends_str);
// 				g_string_append(backends_str, ",");
// 				g_string_append(backends_str, backend->addr->name->str);
// 			}
// 		}
// 		else if (backend->type == BACKEND_TYPE_RO)
// 		{
// 			if (r_backends_cnt++ == 0)
// 			{
// 				r_backends_str = g_string_new_len(NULL, 100);
// 				g_string_append(r_backends_str, backend->addr->name->str);
// 			}
// 			else
// 			{
// 				g_assert(r_backends_str);
// 				g_string_append(r_backends_str, ",");
// 				g_string_append(r_backends_str, backend->addr->name->str);
// 			}
// 		}
// 		else
// 			g_assert(0);
// 	}

	g_assert(proxy_plugin != NULL);
	
	///////////////////admin
    if (admin_plugin != NULL)
    {
        admin_plugin->get_ini_str(buf, 65535, admin_plugin->config, srv);
        g_string_append(new_str, buf);
    }

	///////////////////proxy
    if (proxy_plugin != NULL)
    {
        proxy_plugin->get_ini_str(buf, 65535, proxy_plugin->config, srv);
        g_string_append(new_str, buf);
    }
// 	proxy_config = (struct chassis_proxy_plugin_config*)proxy_plugin->config;
// 
// 	sprintf(buf, ini_str_proxy1, 
// 		proxy_plugin ? "" : "#",								proxy_plugin ? proxy_config->address : "0.0.0.0:4040",
// 		proxy_plugin && backends_str ? "" : "#",				proxy_plugin && backends_str ? backends_str->str : "ip:port",
// 		proxy_plugin && r_backends_str ? "" : "#",				proxy_plugin && r_backends_str ? r_backends_str->str : "ip:port",
// 		proxy_plugin && proxy_config->lua_script ? "" : "#",	proxy_plugin && proxy_config->lua_script ? proxy_config->lua_script : "file_name");
// 
// 	g_string_append(new_str, buf);
// 	
// 	sprintf(buf, ini_str_proxy2,
// 		proxy_plugin && proxy_config->fix_bug_25371 ? "" : "#",
// 		proxy_plugin && proxy_config->pool_change_user == 0 ? "" : "#",
// 		proxy_plugin && proxy_config->profiling == 0 ? "" : "#",
// 		proxy_plugin && proxy_config->start_proxy == 0 ? "" : "#");
// 	g_string_append(new_str, buf);

	///////////////////app
	g_assert(srv->event_thread_count > 0);
	sprintf(buf, ini_str_app1,
		srv->base_dir_org ? "" : "#",			srv->base_dir_org ? srv->base_dir_org : "base_dir_path",
		"", srv->event_thread_count,
 		srv->log_file_name_org ? "" : "#",		srv->log_file_name_org ? srv->log_file_name_org : "log_file_name",
 		"",										chassis_log_get_level_name(srv->log->min_lvl),
 		"",										plugins_buf,
#ifndef _WIN32
 		srv->auto_restart ? "" : "#",
		srv->daemon_mode ? "" : "#","",srv->conn_log == TRUE ? "true" : "false","",ignore_str->str);
#else
 		"#",
		"#","",srv->conn_log == TRUE ? "true" : "false","",ignore_str->str);
#endif

	g_string_append(new_str, buf);

	sprintf(buf, ini_str_app2,
		srv->max_files_number ? "" : "#",		srv->max_files_number ? srv->max_files_number : 0,
		srv->lua_cpath_org ? "" : "#",			srv->lua_cpath_org ? srv->lua_cpath_org : "dir_name",
		srv->lua_path_org ? "" : "#",			srv->lua_path_org ? srv->lua_path_org : "dir_name",
		srv->invoke_dbg_on_crash ? "" : "#",
		srv->log->use_syslog ? "" : "#",
		srv->pid_file_org ? "" : "#",			srv->pid_file_org ? srv->pid_file_org : "file_name",
		srv->plugin_dir_org ? "" : "#",			srv->plugin_dir_org ? srv->plugin_dir_org : "dir_name",
		srv->user ? "" : "#",					srv->user ? srv->user : "user_name");

	g_string_append(new_str, buf);

// 	if (backends_str)
// 		g_string_free(backends_str, TRUE);
// 
// 	if (r_backends_str)
// 		g_string_free(r_backends_str, TRUE);

	g_assert (srv->default_file);

	ini_file = fopen(srv->default_file, "w+");
	if (NULL == ini_file)
	{
		g_string_free(new_str, TRUE);

		g_critical("%s: Can't open ini file %s",
			G_STRLOC, srv->default_file);
		return EC_ADMIN_REFRESH_WIRTE_FILE_FAIL;
	}

	if (fprintf(ini_file, new_str->str) < 0)
		ret = EC_ADMIN_REFRESH_WIRTE_FILE_FAIL;
	else
		ret = EC_ADMIN_SUCCESS;

    fflush(ini_file);

	fclose(ini_file);

	g_string_free(new_str, TRUE);

	return ret;
}

int
admin_read_users_file(
    chassis               *chas,
    chassis_plugin_config *config
)
{
    FILE*       f;
    gchar       buf[1000];

    g_assert(config->users_file);
    g_assert(chas->user_ip_set == NULL);

    chas->user_ip_set = g_set_new(g_str_hash, g_str_equal, g_free);
    chas->set_mutex   = g_mutex_new();

    f = fopen(config->users_file, "r");
    if (f == NULL)
    {
        g_error("%s: Could not open users file: %s", G_STRLOC, config->users_file);
        return -1;      
    }

    g_mutex_lock(chas->set_mutex);
    while (fgets(buf, 1000, f))
    {
        guint       len = strlen(buf);
        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        g_set_insert(chas->user_ip_set, g_strdup(buf));
    }
    g_mutex_unlock(chas->set_mutex);
    
    fclose(f);

    return 0;
}

struct admin_hash_file_struct 
{
    FILE*   open_file;
    gint    error_no;
};

typedef struct admin_hash_file_struct admin_hash_file_t;


void
admin_write_users_file_func(
    gpointer                key,
    gpointer                key2,
    admin_hash_file_t*      hash_file
)
{
    if (hash_file->error_no < 0)
        return;
    
    if (fprintf(hash_file->open_file, "%s\n", key) < 0)
        hash_file->error_no = -1;
}

int
admin_write_users_file(
    chassis               *chas
)
{
    FILE*       f;
    guint       i;
    admin_hash_file_t   hash_file;
    gint        ret = EC_ADMIN_SUCCESS;
    
    chassis_plugin_config *config = NULL;
    
    for (i = 0; i < chas->modules->len; ++i)
    {
        chassis_plugin*     plugin;

        plugin = g_ptr_array_index(chas->modules, i);

        if (strcmp(plugin->name, "admin") == 0)
        {
            config = plugin->config;
            break;
        }
    }
    
    g_assert(config != NULL);
    
    f = fopen(config->users_file, "w+");
    if (f == NULL)
    {
        g_critical("%s: Admin refresh user, could not open users file: %s\n", G_STRLOC, config->users_file);
        return EC_ADMIN_REFRESH_USERS_NO_CONS_FILE;
    }

    hash_file.open_file = f;
    hash_file.error_no = 0;

    //已保护
    //g_mutex_lock(chas->set_mutex);

    g_hash_table_foreach(chas->user_ip_set, admin_write_users_file_func, &hash_file);

    if (hash_file.error_no < 0)
    {
        g_critical("%s: Admin refresh user, write file: %s error\n", G_STRLOC, config->users_file);
        ret = EC_ADMIN_REFRESH_USERS_WIRTE_FILE_FAIL;
    }

    //g_mutex_unlock(chas->set_mutex);

    fflush(f);

    fclose(f);

    return ret;
}


#include "network-address.h"

#define MAX_IP_PORT_STRING_LEN 100


struct admin_network_addr_struct 
{
	gchar						ip_address[MAX_IP_PORT_STRING_LEN + 1];
	gint						port;
	network_address*			addr;
};

typedef struct admin_network_addr_struct admin_network_addr_t;

static
void
admin_print_all_backend_cons(
	chassis*			srv
)
{
	GPtrArray*				cons;
	guint					i;
	network_mysqld_con*		con;
	guint					invalid_cnt = 0;
	guint					valid_cnt = 0;
	gchar*					state_str[] = {
		"CON_STATE_INIT",
		"CON_STATE_CONNECT_SERVER", 
		"CON_STATE_READ_HANDSHAKE", 
		"CON_STATE_SEND_HANDSHAKE", 
		"CON_STATE_READ_AUTH",
		"CON_STATE_SEND_AUTH",
		"CON_STATE_READ_AUTH_RESULT",
		"CON_STATE_SEND_AUTH_RESULT",
		"CON_STATE_READ_AUTH_OLD_PASSWORD", 
		"CON_STATE_SEND_AUTH_OLD_PASSWORD", 
		"CON_STATE_READ_QUERY",
		"CON_STATE_SEND_QUERY",
		"CON_STATE_READ_QUERY_RESULT",
		"CON_STATE_SEND_QUERY_RESULT",
		"CON_STATE_CLOSE_CLIENT", 
		"CON_STATE_SEND_ERROR",
		"CON_STATE_ERROR",
		"CON_STATE_CLOSE_SERVER = 17",
		"CON_STATE_READ_LOCAL_INFILE_DATA",
		"CON_STATE_SEND_LOCAL_INFILE_DATA",
		"CON_STATE_READ_LOCAL_INFILE_RESULT",
		"CON_STATE_SEND_LOCAL_INFILE_RESULT",
	};

	cons = srv->priv->cons;
	g_message("admin_print_all_backend_cons start...");
	g_mutex_lock(srv->priv->cons_mutex);
	for (i = 0; i < cons->len; ++i)
	{
		con = g_ptr_array_index(cons, i);

		if (con->server && con->server->backend_idx != -1)
		{
			if (con->server->disconnect_flag)
			{
				invalid_cnt ++;
				g_message("invalid connection: server: %s/%d, client : %s/%d, state : %s", con->server->dst->name->str, con->server->fd, con->client->src->name->str, con->client->fd, state_str[con->state]);
			}
			else
			{
				valid_cnt ++;
				g_message("valid connection: server: %s/%d, client : %s/%d, state : %s", con->server->dst->name->str, con->server->fd, con->client->src->name->str, con->client->fd, state_str[con->state]);
			}
		}
	}
	g_message("admin_print_all_backend_cons end... connections cnt : %d, invalid cnt : %d, valid cnt %d", cons->len, invalid_cnt, valid_cnt);
	g_mutex_unlock(srv->priv->cons_mutex);
	
}

void
admin_network_addr_free(
	gpointer*			addr_ptr						
)
{
	admin_network_addr_t*			addr;


	addr	= (admin_network_addr_t*)addr_ptr;

	network_address_free(addr->addr);

	g_free(addr);
}

static
gint
admin_refresh_backends(
	network_mysqld_con*			con,
	GPtrArray*					backend_addr_str_array,
	gint						fail_flag
)
{
	chassis*					srv;
	network_backends_t*			backends;
	GPtrArray*					cons; 
	gchar*						s;
	gchar*						new_backend_addr;
	guint						i;
	//gchar						ip_address[MAX_IP_PORT_STRING_LEN + 1];
	admin_network_addr_t*		addr;	
	GPtrArray*					addr_array;
	gint						ret = EC_ADMIN_SUCCESS;
	gboolean					all_same_flag = 1;
	guint						server_cnt = 0;
	guint						client_cnt = 0;

	srv			= con->srv;
	backends	= srv->priv->backends;
	cons		= srv->priv->cons;

	//for test
	if (fail_flag == 1000)
	{
		admin_print_all_backend_cons(con->srv);
		return EC_ADMIN_SUCCESS;
	}

	if (backend_addr_str_array->len != backends->backends->len)
	{
		g_critical("%s: Number of refresh backends num is not matched, new backends :%d, orignal backends : %d",
					G_STRLOC, backend_addr_str_array->len , backends->backends->len);
		return EC_ADMIN_REFRESH_BACKENDS_FAIL;
	}

	if (fail_flag != 0 && fail_flag != 1)
	{
		g_critical("%s: Fail flag of refresh backends must be 0 or 1, but the flag is %d",
					G_STRLOC, fail_flag);
		return EC_ADMIN_REFRESH_BACKENDS_FAIL;
	}
	
	addr_array	= g_ptr_array_new();

	/* 1. 测试DR连通性 */
	for (i = 0; i < backend_addr_str_array->len; ++i)
	{
		new_backend_addr = g_ptr_array_index(backend_addr_str_array, i);
		addr			 = g_new0(admin_network_addr_t, 1);
		g_ptr_array_add(addr_array, addr);

		s = strchr(new_backend_addr, ':');

		if (NULL != s) 
		{
			gint				len;
			char *				port_err = NULL;
			network_backend_t*	backend;

			backend = g_ptr_array_index(backends->backends, i);

			//check whether all backends are same
			//to do check backend:127.0.0.1:3306, addr:ip:3306? 
			if (all_same_flag && g_strcasecmp(new_backend_addr, backend->addr->name->str) != 0 ||
					backend->state == BACKEND_STATE_DOWN)
			{
				all_same_flag = 0;
			}
			

			len = s - new_backend_addr;
			if (len <=  MAX_IP_PORT_STRING_LEN)
			{
				memcpy(addr->ip_address, new_backend_addr, len);
				addr->ip_address[len] = '\0';

				addr->port = strtoul(s + 1, &port_err, 10);
			}

			if (len > MAX_IP_PORT_STRING_LEN ||
					*(s + 1) == '\0') 
			{
				g_critical("%s: Reload IP-address has to be in the form [<ip>][:<port>], is '%s'. No port number",
					G_STRLOC, new_backend_addr);
				ret = EC_ADMIN_REFRESH_BACKENDS_FAIL;
			} 
			else if (*port_err != '\0') 
			{
				g_critical("%s: Reload IP-address has to be in the form [<ip>][:<port>], is '%s'. Failed to parse the port at '%s'",
					G_STRLOC, new_backend_addr, port_err);
				ret = EC_ADMIN_REFRESH_BACKENDS_FAIL;
			} 
			else 
			{
				addr->addr = network_address_new();
				if (network_address_set_address_ip(addr->addr, addr->ip_address, addr->port))
				{
					g_critical("%s: Reload IP-address %s : %d error",
						G_STRLOC, addr->ip_address, addr->port);
					ret = EC_ADMIN_REFRESH_BACKENDS_FAIL;
				}
				//ping the ip address and port;
				//ret = network_address_set_address_ip(addr, ip_address, port);
				//to do
			}
		}
		else
			ret = EC_ADMIN_REFRESH_BACKENDS_FAIL;
		
		if (EC_ADMIN_REFRESH_BACKENDS_FAIL == ret)
		{
			g_ptr_array_free_all(addr_array, admin_network_addr_free);
			return ret;
		}
	}

	//backends are same
	if (all_same_flag)
	{
		g_ptr_array_free_all(addr_array, admin_network_addr_free);
		return EC_ADMIN_SUCCESS;
	}

	/* 2. 置当前所有backends为down */
	g_mutex_lock(backends->backends_mutex);
	for (i = 0; i < backends->backends->len; ++i)
	{
		network_backend_t*		backend;

		backend = g_ptr_array_index(backends->backends, i);
	
		backend->state = BACKEND_STATE_DOWN;	
	}
	g_mutex_unlock(backends->backends_mutex);	

	/* 3. 当前backend为新地址 */
	g_mutex_lock(backends->backends_mutex);
	for (i = 0; i < backends->backends->len; ++i)
	{
		network_backend_t*		backend;

		backend = g_ptr_array_index(backends->backends, i);

		addr = g_ptr_array_index(addr_array, i);

		network_address_copy(backend->addr, addr->addr);
	}
	g_mutex_unlock(backends->backends_mutex);


	/* 4. 关闭proxy当前所有连接 */
	g_mutex_lock(srv->priv->cons_mutex);
	for (i = 0; i < cons->len; ++i)
	{
		con = g_ptr_array_index(cons, i);

		//区分了是否为backends的连接
		if (con->server && con->server->backend_idx != -1)
		{
			//g_assert(con->server->fd != -1);
			if (con->server->fd != -1)
			{
				//closesocket(con->server->fd);
				con->server->fd_bak	= con->server->fd; /* 后端连接暂不关闭，让其正常处理正在进行的事件 */
				con->server->fd		= -1;
				con->server->disconnect_flag = 1;
				server_cnt++;
			}

			//g_assert(con->client && con->client->fd != -1);
			if (con->client && con->client->fd != -1)
			{
// 				int c_fd = con->client->fd;
// 				con->client->fd		= -1;
// 				closesocket(c_fd);						/* 需主动关闭前端fd，防止前端一直等待，但会导致con资源没有释放 */
				client_cnt++;
			}

			/* 以上操作可能产生一种情况：客户端请求已在DB执行成功，但前端认为连接已断开 */

			switch(con->state)
			{
			case CON_STATE_CLOSE_CLIENT:
			case CON_STATE_CLOSE_SERVER:
			case CON_STATE_SEND_ERROR:
			case CON_STATE_ERROR:
				break;

			case CON_STATE_INIT:
			case CON_STATE_CONNECT_SERVER:
			case CON_STATE_READ_HANDSHAKE:
			case CON_STATE_SEND_HANDSHAKE:
			case CON_STATE_READ_AUTH:
			case CON_STATE_SEND_AUTH:
			case CON_STATE_READ_AUTH_RESULT:
			case CON_STATE_SEND_AUTH_RESULT:
			case CON_STATE_READ_AUTH_OLD_PASSWORD:
			case CON_STATE_SEND_AUTH_OLD_PASSWORD:
				break;

			case CON_STATE_READ_QUERY:
			case CON_STATE_SEND_QUERY:
				break;

			case CON_STATE_READ_QUERY_RESULT:
			case CON_STATE_SEND_QUERY_RESULT:
// 				//需要主动关闭连接
// 				if (fail_flag == 1)
// 				{
// 					if (con->client->fd != -1)
// 					{
// 						closesocket(con->client->fd);
// 						con->client->fd = -1;
// 					}
// 				}
				break;

			case CON_STATE_READ_LOCAL_INFILE_DATA:
			case CON_STATE_SEND_LOCAL_INFILE_DATA:
			case CON_STATE_READ_LOCAL_INFILE_RESULT:
			case CON_STATE_SEND_LOCAL_INFILE_RESULT:
				break;
			}
			
		}
	}
	g_message("%s reload backends: connection count %d, close server count %d, close client count %d",
				G_STRLOC, srv->priv->cons->len, server_cnt, client_cnt);
	g_mutex_unlock(srv->priv->cons_mutex);	

	if (ret != EC_ADMIN_SUCCESS)
		goto destroy_end;

    /* 5. 再把后端状态置为unknown，接收新连接 */
    g_mutex_lock(backends->backends_mutex);
    for (i = 0; i < backends->backends->len; ++i)
    {
        network_backend_t*		backend;

        backend = g_ptr_array_index(backends->backends, i);

        backend->state = BACKEND_STATE_UNKNOWN;	
    }
    g_mutex_unlock(backends->backends_mutex);

	/* 6. 刷新配置 */
	ret = admin_configure_flush_to_file(srv);

destroy_end:
	g_ptr_array_free_all(addr_array, admin_network_addr_free);
	return ret;
}

//

#define ADMIN_REFRESH_TYPE_BACKENDS 0
#define ADMIN_REFRESH_TYPE_USERS    1
#define ADMIN_REFRESH_TYPE_CONNLOG  2

/*
    根据存储函数的字符参数以及逗号分隔符获得字符数组，并返回读取位置
*/
static
gchar*
admin_get_str_array_from_proc_strarg(
    gchar*          p,
    gchar*          p_end,
    GPtrArray**     p_buffer_arrary
)
{
    gchar*	cmd_str = NULL;
    gchar	buffer[MAX_IP_PORT_STRING_LEN + 1];
    int		index = 0;
    GPtrArray*		buffer_array = *p_buffer_arrary;

    if (*p != '\'')
    {
        return NULL;
    }

    p++;

    /* 处理第一个参数，根据逗号分隔，得到字符数组 */
    while(p && 
        *p != '\'' && 
        p != p_end)
    {
        if (MAX_IP_PORT_STRING_LEN == index)
        {
            return NULL;
        }
        else if (*p == ',')
        {
            if (index > 0)
            {
                buffer[index] = '\0';
                g_ptr_array_add(buffer_array, g_strdup(g_strstrip(buffer)));
            }
            index = 0;
            p++;

            continue;
        }

        buffer[index++] = *(p++);
    }

    if (index > 0)
    {
        buffer[index] = '\0';
        g_ptr_array_add(buffer_array, g_strdup(g_strstrip(buffer)));
    }

    if (p == p_end || *p != '\'')
    {
        return NULL;
    }

    p++;

    //skip the space, \t 
    while (p != p_end && g_ascii_isspace(*p))
        p++;

    return p;
}

/* add by huibohuang */
static
gint
admin_refresh_connlog(
	network_mysqld_con*         con,
	gchar*					    conn_flag
)
{
	chassis*	srv;
	gint		ret = 0;
	gint		new_conn_flag;
	gchar*		fail_flag_err = NULL;

	srv = con->srv;
	new_conn_flag = strtoul(conn_flag,&fail_flag_err, 10);

	if (fail_flag_err[0] != '\0')
	{
		g_critical("%s: Fail flag of refresh connlog must be 0 or 1, but the flag is %s",
			G_STRLOC, fail_flag_err);
		ret = EC_ADMIN_REFRESH_CONNLOG_FAIL;
		return ret;
	}

	if (new_conn_flag != 0 && new_conn_flag != 1)
	{
		g_critical("%s: Fail flag of refresh connlog must be 0 or 1, but the flag is %d",
			G_STRLOC, new_conn_flag);
		ret = EC_ADMIN_REFRESH_CONNLOG_FAIL;
		return ret;
	}
	srv->conn_log = new_conn_flag;
	ret = admin_configure_flush_to_file(srv);

	return ret;
}

static
gint
admin_refresh_users(
    network_mysqld_con*         con,
    GPtrArray*                  user_array,
    gchar                       action_flag
)
{
    chassis*        chas;
    gint            ret = 0;
    guint           i;

    chas = con->srv;

    g_mutex_lock(chas->set_mutex);

    if (action_flag == '+')
    {
        for (i = 0; i < user_array->len; ++i)
        {
            g_set_insert(chas->user_ip_set, g_strdup(g_ptr_array_index(user_array, i)));
        }
    }
    else if (action_flag == '-')
    {
        for (i = 0; i < user_array->len; ++i)
        {
            g_set_remove(chas->user_ip_set, g_ptr_array_index(user_array, i));
        }
    }
    else if (action_flag == '=')
    {
        g_set_remove_all(chas->user_ip_set);

        for (i = 0; i < user_array->len; ++i)
        {
            g_set_insert(chas->user_ip_set, g_strdup(g_ptr_array_index(user_array, i)));
        }
    }
    else
    {
        g_mutex_unlock(chas->set_mutex);
        ret = EC_ADMIN_REFRESH_USERS_FAIL;

        return ret;
    }
    
    ret = admin_write_users_file(chas);

    g_mutex_unlock(chas->set_mutex);

    return ret;
}

static  
gint
admin_refresh_if_necessary(
	network_mysqld_con*			con
)
{
	char command = -1;
	network_socket *recv_sock = con->client;
	GList   *chunk  = recv_sock->recv_queue->chunks->head;
	GString *packet = chunk->data;

	if (packet->len < NET_HEADER_SIZE) 
		return EC_ADMIN_UNKNOWN; /* packet too short */

	command = packet->str[NET_HEADER_SIZE + 0];

#ifdef _VINCHEN_TEST2
    if (COM_QUERY == command)
    {  
        gchar*	cmd_str = NULL;

        cmd_str = g_strndup(&packet->str[NET_HEADER_SIZE + 1], packet->len - NET_HEADER_SIZE - 1);
        printf("query : %s\n", cmd_str);

        g_free(cmd_str);
    }
    else
    {
        printf("not a query : %d\n", command);
    }
#endif // _VINCHEN_TEST2

	/* not a query */
	if (COM_QUERY != command) 
		return EC_ADMIN_UNKNOWN;

	//刷新配置
	if (packet->len - NET_HEADER_SIZE - 1 >= 0)
	{
		gchar*	first_arg;
		gchar*	p;
		gchar*	s;
		gchar*	p_end;
		gchar*	cmd_str = NULL;
        gchar*  second_arg = NULL;
		int		index = 0;
		GPtrArray*		buffer_array;
		gint	ret;
	    gint    refresh_type;

		cmd_str = g_strndup(&packet->str[NET_HEADER_SIZE + 1], packet->len - NET_HEADER_SIZE - 1);
        if (g_ascii_strncasecmp(cmd_str, C("refresh_backends(")) == 0)
        {
		    //first_arg = &packet->str[NET_HEADER_SIZE + 1 + sizeof("refresh_backends(") - 1];
            first_arg = cmd_str + sizeof("refresh_backends(") - 1;
            refresh_type = ADMIN_REFRESH_TYPE_BACKENDS;
        }
        else if (g_ascii_strncasecmp(cmd_str, C("refresh_users(")) == 0)
        {
		    //first_arg = &packet->str[NET_HEADER_SIZE + 1 + sizeof("refresh_users(") - 1];
            first_arg = cmd_str + sizeof("refresh_users(") - 1;
            refresh_type = ADMIN_REFRESH_TYPE_USERS;
        }
		else if(g_ascii_strncasecmp(cmd_str, C("refresh_connlog(")) == 0)
		{
			//add by huibohuang
			first_arg = cmd_str + sizeof("refresh_connlog(") - 1;
			refresh_type = ADMIN_REFRESH_TYPE_CONNLOG;
		}
        else 
        {
            return EC_ADMIN_UNKNOWN;
        }
             
		p = first_arg;
		buffer_array = g_ptr_array_new();
		
		if(refresh_type == ADMIN_REFRESH_TYPE_CONNLOG){
			if (NULL == (s = strchr(p, ')')) || s - p == 0){
				ret = EC_ADMIN_FAIL;
				goto    destroy_end;
			}
			first_arg = g_strndup(p, s-p);
			g_strstrip(first_arg);
		}else{
			p_end = packet->str + packet->len;
			/* 分析第一个字符参数，得到字符数组 */
			p = admin_get_str_array_from_proc_strarg(p, p_end, &buffer_array);
			if (p == NULL)
			{
				ret = EC_ADMIN_FAIL;
				goto    destroy_end;
			}
			
			//modify by huibohuang,refresh_connlog不需要第二个参数
			if (*p != ',')
			{
				ret = EC_ADMIN_FAIL;
				goto    destroy_end;
			}

			p++;

			/* 获得第二个参数的 */
			if (NULL == (s = strchr(p, ')')) || s - p == 0)
			{
				ret = EC_ADMIN_FAIL;
				goto    destroy_end;
			}

			second_arg = g_strndup(p, s-p);
			g_strstrip(second_arg);
			
		}
        //根据不同类型进行分析
        if (refresh_type == ADMIN_REFRESH_TYPE_BACKENDS)
        {
            gint	fail_flag;
            gchar*	fail_flag_err = NULL;

            fail_flag = strtoul(second_arg, &fail_flag_err, 10);
            if (fail_flag_err[0] != '\0')
            {
                ret = EC_ADMIN_FAIL;
                goto    destroy_end;
            }

            g_critical("%s: Executing %s", G_STRLOC, cmd_str);

            //backend_buf should by ip:port, to be new backend;
            ret = admin_refresh_backends(con, buffer_array, fail_flag);

            switch(ret)
            {
            case EC_ADMIN_SUCCESS:
                network_mysqld_con_send_ok_full(con->client, 0, 0, 0, 0);
                break;

            case EC_ADMIN_REFRESH_BACKENDS_FAIL:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh backends failed"), 4041, "2800");
                break;

            case EC_ADMIN_REFRESH_NO_CONS_FILE:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh backends success, but there is no configure file"), 4042, "2800");
                break;

            case EC_ADMIN_REFRESH_WIRTE_FILE_FAIL:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh backends success, but write configure file failed"), 4043, "2800");
                break;

            default:
                g_assert(0);
                break;
            }        
        }
        else if (refresh_type == ADMIN_REFRESH_TYPE_USERS)
        {
            gchar action_flag;
            if (second_arg[0] != '\'' ||
                second_arg[2] != '\'')
            {
                ret = EC_ADMIN_FAIL;
                goto    destroy_end;
            }

            action_flag = second_arg[1];

            ret = admin_refresh_users(con, buffer_array, action_flag);

            switch(ret)
            {
            case EC_ADMIN_SUCCESS:
                network_mysqld_con_send_ok_full(con->client, 0, 0, 0, 0);
                break;

            case EC_ADMIN_REFRESH_USERS_FAIL:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh users failed"), 4051, "2800");
                break;

            case EC_ADMIN_REFRESH_USERS_NO_CONS_FILE:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh users success, but there is no configure file"), 4052, "2800");
                break;

            case EC_ADMIN_REFRESH_USERS_WIRTE_FILE_FAIL:
                network_mysqld_con_send_error_full(con->client, C("Admin refresh users success, but write configure file failed"), 4053, "2800");
                break;

            default:
                g_assert(0);
                break;
            }        
        }else if(refresh_type == ADMIN_REFRESH_TYPE_CONNLOG)
		{
			ret = admin_refresh_connlog(con, first_arg);

			switch(ret)
			{
			case EC_ADMIN_SUCCESS:
				network_mysqld_con_send_ok_full(con->client, 0, 0, 0, 0);
				break;

			case EC_ADMIN_REFRESH_CONNLOG_FAIL:
				network_mysqld_con_send_error_full(con->client, C("Admin refresh connlog failed"), 4061, "2800");
				break;

			case EC_ADMIN_REFRESH_NO_CONS_FILE:
				network_mysqld_con_send_error_full(con->client, C("Admin refresh connlog success, but there is no configure file"), 4062, "2800");
				break;

			case EC_ADMIN_REFRESH_WIRTE_FILE_FAIL:
				network_mysqld_con_send_error_full(con->client, C("Admin refresh connlog success, but write configure file failed"), 4063, "2800");
				break;

			default:
				g_assert(0);
				break;
			}   
		}

destroy_end:
        if (ret == EC_ADMIN_FAIL)
        {
            if (refresh_type == ADMIN_REFRESH_TYPE_BACKENDS)
            {
                network_mysqld_con_send_error_full(con->client, C("Admin refresh backends failed, error input"), 4041, "2800");
            }
            else if (refresh_type == ADMIN_REFRESH_TYPE_USERS)
            {
                network_mysqld_con_send_error_full(con->client, C("Admin refresh uers failed, error input"), 4051, "2800");
            }else if(refresh_type == ADMIN_REFRESH_TYPE_CONNLOG)
			{
				network_mysqld_con_send_error_full(con->client, C("Admin refresh connlog failed, error input"), 4061, "2800");
			}

            g_critical("%s: admin refresh error input %s",
                G_STRLOC, cmd_str);
        }

        g_ptr_array_free_all(buffer_array, g_free);
        
        g_free(cmd_str);
        if (second_arg != NULL)
            g_free(second_arg);
        
		return ret;
	}

	return EC_ADMIN_UNKNOWN;
}

void
admin_get_users_resultset_func(
    gpointer            key,
    gpointer            key2,
    GPtrArray           *rows                               
)
{
    GPtrArray       *row;

    row = g_ptr_array_new();

    g_ptr_array_add(row, g_strdup(key));
    g_ptr_array_add(rows, row);
}

gint
admin_handle_normal_query(
	network_mysqld_con*			con                              
)
{
    gsize           i, j;
    GPtrArray       *fields;
    GPtrArray       *rows;
    GPtrArray       *row;

    network_socket  *recv_sock = con->client;
    GList           *chunk  = recv_sock->recv_queue->chunks->head;
    GString         *packet = chunk->data;
    gchar           command;
    gint            ret = EC_ADMIN_UNKNOWN;
	
	/*  add by huibohuang
	 */
	GPtrArray*		cons;
	chassis*		srv;
	network_mysqld_con*		tcon;

    if (packet->len < NET_HEADER_SIZE) 
        return EC_ADMIN_UNKNOWN; /* packet too short */

    command = packet->str[NET_HEADER_SIZE + 0];
    if (COM_QUERY != command) 
        return EC_ADMIN_UNKNOWN;

    fields = NULL;
    rows = NULL;
    row = NULL;

    if (0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("select * from user"))) 
    {
        MYSQL_FIELD *field;
        GSet        *set;

        fields = network_mysqld_proto_fielddefs_new();

        field = network_mysqld_proto_fielddef_new();
        field->name = g_strdup("user@ip");
        field->type = FIELD_TYPE_VAR_STRING;
        g_ptr_array_add(fields, field);

        rows = g_ptr_array_new();
        set = con->srv->user_ip_set;
        g_hash_table_foreach(set, admin_get_users_resultset_func, rows);

        network_mysqld_con_send_resultset(con->client, fields, rows);

        ret = EC_ADMIN_SUCCESS;
    }
    else if(0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("show balances")))
    {
        //add by vinchen 
        MYSQL_FIELD *field;
        gchar id_str[50];
        gchar*	cols[] = {"Id","Count"};

        fields = network_mysqld_proto_fielddefs_new();
        for (i = 0; i < 2; ++i){
            field = network_mysqld_proto_fielddef_new();
            field->name = g_strdup(cols[i]);
            field->type = FIELD_TYPE_VAR_STRING;
            g_ptr_array_add(fields,field);
        }

        rows = g_ptr_array_new();
        srv = con->srv;
        for (i = 0; i < (unsigned)srv->event_thread_count; ++i)
        {
            chassis_event_thread_t * event_thread = con->srv->threads->event_threads->pdata[i];

            row = g_ptr_array_new();

            snprintf(id_str, sizeof(id_str) - 1 , "%d", i);
            g_ptr_array_add(row, g_strdup(id_str));

            snprintf(id_str, sizeof(id_str) - 1 , "%ul", event_thread->event_add_cnt);
            g_ptr_array_add(row, g_strdup(id_str));

            g_ptr_array_add(rows, row);
        }

        network_mysqld_con_send_resultset(con->client, fields, rows);
        ret = EC_ADMIN_SUCCESS;
    }
	else if(0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("show processlist")))
	{
		//add by huibohuang
		MYSQL_FIELD *field;
		gchar thread_id_str[50];
		gchar host[50];
		gchar ftime_str[20];
		GTimeVal	now;
		gint64		tdiff;
		gchar*	cols[] = {"Id","User","Host","db","Time"};
		
		fields = network_mysqld_proto_fielddefs_new();
		for (i = 0; i < 5; ++i){
			field = network_mysqld_proto_fielddef_new();
			field->name = g_strdup(cols[i]);
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields,field);
		}

		rows = g_ptr_array_new();
		srv = con->srv;
		cons = srv->priv->cons;

		g_mutex_lock(srv->priv->cons_mutex);
		for (i = 0; i < cons->len; ++i)
		{
			tcon = g_ptr_array_index(cons, i);
			if (tcon->server && tcon->client && tcon->client->src)
			{
				if(tcon->server->challenge && tcon->client->response && tcon->client->response->username &&
					tcon->client->default_db){
					row = g_ptr_array_new();

					snprintf(thread_id_str, sizeof(thread_id_str) - 1 , "%d",tcon->server->challenge->thread_id);
					g_ptr_array_add(row, g_strdup(thread_id_str));
										
				    g_ptr_array_add(row, g_strdup(tcon->client->response->username->str));
														
					// 目前一定是ipv4
					g_assert(tcon->client->src->addr.common.sa_family == AF_INET);
					snprintf(host, sizeof(host) - 1, "%s:%d",inet_ntoa(tcon->client->src->addr.ipv4.sin_addr),tcon->client->src->addr.ipv4.sin_port);
					g_ptr_array_add(row, g_strdup(host));

					if(tcon->client->default_db->len > 0){
						g_ptr_array_add(row, g_strdup(tcon->client->default_db->str));
					}else{
						g_ptr_array_add(row, g_strdup("NULL"));
					}

					g_get_current_time(&now);
					ge_gtimeval_diff(&(tcon->start_time), &now, &tdiff);
					tdiff /= G_USEC_PER_SEC;
					snprintf(ftime_str, sizeof(ftime_str) -1, "%d",tdiff);
					g_ptr_array_add(row, g_strdup(ftime_str));

					g_ptr_array_add(rows, row);
				}
			}
		}
		g_mutex_unlock(srv->priv->cons_mutex);

		network_mysqld_con_send_resultset(con->client, fields, rows);
		ret = EC_ADMIN_SUCCESS;
	}

    /* clean up */
    if (fields) {
        network_mysqld_proto_fielddefs_free(fields);
        fields = NULL;
    }

    if (rows) {
        for (i = 0; i < rows->len; i++) {
            row = rows->pdata[i];

            for (j = 0; j < row->len; j++) {
                g_free(row->pdata[j]);
            }

            g_ptr_array_free(row, TRUE);
        }
        g_ptr_array_free(rows, TRUE);
        rows = NULL;
    }

    return ret;
}

gint
admin_process_new_conn_if_necessary(
    network_mysqld_con*			con                         
)
{
    char command = -1;
    network_socket *recv_sock = con->client;
    GList   *chunk  = recv_sock->recv_queue->chunks->head;
    GString *packet = chunk->data;

    if (packet->len < NET_HEADER_SIZE) 
        return EC_ADMIN_UNKNOWN; /* packet too short */

    command = packet->str[NET_HEADER_SIZE + 0];

    if (COM_INIT_DB == command)
    {
        return 0;
    }

    if (COM_QUERY == command)
    {
        gchar*	cmd_str = NULL;

        cmd_str = g_strndup(&packet->str[NET_HEADER_SIZE + 1], packet->len - NET_HEADER_SIZE - 1);
        
        if (0 == g_ascii_strncasecmp(cmd_str, C("set autocommit=1")) ||
            0 == g_ascii_strncasecmp(cmd_str, C("set autocommit=0")))
        {
            g_free(cmd_str);
            return 0;
        }

        g_free(cmd_str);
    }

    return -1;
}

/* end add by vinchen/CFR */

static network_mysqld_lua_stmt_ret admin_lua_read_query(network_mysqld_con *con) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	char command = -1;
	network_socket *recv_sock = con->client;
	GList   *chunk  = recv_sock->recv_queue->chunks->head;
	GString *packet = chunk->data;

	if (packet->len < NET_HEADER_SIZE) return PROXY_SEND_QUERY; /* packet too short */

	command = packet->str[NET_HEADER_SIZE + 0];

	if (COM_QUERY == command) {
		/* we need some more data after the COM_QUERY */
		if (packet->len < NET_HEADER_SIZE + 2) return PROXY_SEND_QUERY;

		/* LOAD DATA INFILE is nasty */
		if (packet->len - NET_HEADER_SIZE - 1 >= sizeof("LOAD ") - 1 &&
		    0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("LOAD "))) return PROXY_SEND_QUERY;
	}

	network_injection_queue_reset(st->injected.queries);

	/* ok, here we go */

#ifdef HAVE_LUA_H
	switch(network_mysqld_con_lua_register_callback(con, con->config->lua_script)) {
		case REGISTER_CALLBACK_SUCCESS:
			break;
		case REGISTER_CALLBACK_LOAD_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to load. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
		case REGISTER_CALLBACK_EXECUTE_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to execute. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
	}

	if (st->L) {
		lua_State *L = st->L;
		network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

		g_assert(lua_isfunction(L, -1));
		lua_getfenv(L, -1);
		g_assert(lua_istable(L, -1));

		/**
		 * reset proxy.response to a empty table 
		 */
		lua_getfield(L, -1, "proxy");
		g_assert(lua_istable(L, -1));

		lua_newtable(L);
		lua_setfield(L, -2, "response");

		lua_pop(L, 1);
		
		/**
		 * get the call back
		 */
		lua_getfield_literal(L, -1, C("read_query"));
		if (lua_isfunction(L, -1)) {

			/* pass the packet as parameter */
			lua_pushlstring(L, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);

			if (lua_pcall(L, 1, 1, 0) != 0) {
				/* hmm, the query failed */
				g_critical("(read_query) %s", lua_tostring(L, -1));

				lua_pop(L, 2); /* fenv + errmsg */

				/* perhaps we should clean up ?*/

				return PROXY_SEND_QUERY;
			} else {
				if (lua_isnumber(L, -1)) {
					ret = lua_tonumber(L, -1);
				}
				lua_pop(L, 1);
			}

			switch (ret) {
			case PROXY_SEND_RESULT:
				/* check the proxy.response table for content,
				 *
				 */
	
				if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */
			
					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}
	
				break;
			case PROXY_NO_DECISION:
				/**
				 * PROXY_NO_DECISION and PROXY_SEND_QUERY may pick another backend
				 */
				break;
			case PROXY_SEND_QUERY:
				/* send the injected queries
				 *
				 * injection_new(..., query);
				 * 
				 *  */

				if (st->injected.queries->length) {
					ret = PROXY_SEND_INJECTION;
				}
	
				break;
			default:
				break;
			}
			lua_pop(L, 1); /* fenv */
		} else {
			lua_pop(L, 2); /* fenv + nil */
		}

		g_assert(lua_isfunction(L, -1));

		if (ret != PROXY_NO_DECISION) {
			return ret;
		}
	}
#endif
	return PROXY_NO_DECISION;
}

/**
 * gets called after a query has been read
 *
 * - calls the lua script via network_mysqld_con_handle_proxy_stmt()
 *
 * @see network_mysqld_con_handle_proxy_stmt
 */
NETWORK_MYSQLD_PLUGIN_PROTO(server_read_query) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	network_mysqld_lua_stmt_ret ret;
	gint						reload_flag = EC_ADMIN_UNKNOWN;

	send_sock = NULL;
	recv_sock = con->client;
	st->injected.sent_resultset = 0;

	chunk = recv_sock->recv_queue->chunks->head;

	if (recv_sock->recv_queue->chunks->length != 1) {
		g_message("%s.%d: client-recv-queue-len = %d", __FILE__, __LINE__, recv_sock->recv_queue->chunks->length);
	}
	
	packet = chunk->data;

	//add by vinchen/CFR
    //1. 先分析refresh命令
	reload_flag = admin_refresh_if_necessary(con);
	if (reload_flag == EC_ADMIN_SUCCESS)
	{
		//1.1 若成功，
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		con->state = CON_STATE_SEND_QUERY_RESULT;
		return NETWORK_SOCKET_SUCCESS;
	}
	else if (reload_flag != EC_ADMIN_UNKNOWN)
	{
        //1.2 若失败
        g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		con->state = CON_STATE_SEND_QUERY_RESULT;
		return NETWORK_SOCKET_SUCCESS;
	}
    else
    {
        //2. 若不是refresh命令，尝试select查询，maybe select * from users;
        if (admin_handle_normal_query(con) == EC_ADMIN_SUCCESS)
        {
            g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

            con->state = CON_STATE_SEND_QUERY_RESULT;
            return NETWORK_SOCKET_SUCCESS;
        }
    }

	ret = admin_lua_read_query(con);

	switch (ret) {
	case PROXY_NO_DECISION:
		network_mysqld_con_send_error(con->client, C("need a resultset + proxy.PROXY_SEND_RESULT"));
		con->state = CON_STATE_SEND_ERROR;
		break;
	case PROXY_SEND_RESULT: 
		con->state = CON_STATE_SEND_QUERY_RESULT;
		break; 
	default:
		network_mysqld_con_send_error(con->client, C("need a resultset + proxy.PROXY_SEND_RESULT ... got something else"));

		con->state = CON_STATE_SEND_ERROR;
		break;
	}

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup the admin specific data on the current connection 
 *
 * @return NETWORK_SOCKET_SUCCESS
 */
NETWORK_MYSQLD_PLUGIN_PROTO(admin_disconnect_client) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_scope  *sc = con->srv->priv->sc;

	if (st == NULL) return NETWORK_SOCKET_SUCCESS;
	
#ifdef HAVE_LUA_H
	/* remove this cached script from registry */
	if (st->L_ref > 0) {
		luaL_unref(sc->L, LUA_REGISTRYINDEX, st->L_ref);
	}
#endif

	network_mysqld_con_lua_free(st);

	con->plugin_con_state = NULL;

	return NETWORK_SOCKET_SUCCESS;
}


static int network_mysqld_server_connection_init(network_mysqld_con *con) {
	con->plugins.con_init             = server_con_init;

	con->plugins.con_read_auth        = server_read_auth;

	con->plugins.con_read_query       = server_read_query;
	
	con->plugins.con_cleanup          = admin_disconnect_client;

	return 0;
}

static chassis_plugin_config *network_mysqld_admin_plugin_new(void) {
	chassis_plugin_config *config;

	config = g_new0(chassis_plugin_config, 1);

	return config;
}

static void network_mysqld_admin_plugin_free(chassis_plugin_config *config) {
	if (config->listen_con) {
		/* the socket will be freed by network_mysqld_free() */
	}

	if (config->address) {
		g_free(config->address);
	}

	if (config->admin_username) g_free(config->admin_username);
	if (config->admin_password) g_free(config->admin_password);
	if (config->lua_script) g_free(config->lua_script);
	if (config->users_file) g_free(config->users_file);

	g_free(config);
}

/**
 * add the proxy specific options to the cmdline interface 
 */
static GOptionEntry * network_mysqld_admin_plugin_get_options(chassis_plugin_config *config) {
	guint i;

	static GOptionEntry config_entries[] = 
	{
		{ "admin-address",            0, 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the admin-server (default: :4041)", "<host:port>" },
		{ "admin-username",           0, 0, G_OPTION_ARG_STRING, NULL, "username to allow to log in", "<string>" },
		{ "admin-password",           0, 0, G_OPTION_ARG_STRING, NULL, "password to allow to log in", "<string>" },
		{ "admin-lua-script",         0, 0, G_OPTION_ARG_FILENAME, NULL, "script to execute by the admin plugin", "<filename>" },
		{ "admin-users-file",         0, 0, G_OPTION_ARG_FILENAME, NULL, "white list files of user@ip", "<filename>" },
		{ NULL,                       0, 0, G_OPTION_ARG_NONE,   NULL, NULL, NULL }
	};

	i = 0;
	config_entries[i++].arg_data = &(config->address);
	config_entries[i++].arg_data = &(config->admin_username);
	config_entries[i++].arg_data = &(config->admin_password);
	config_entries[i++].arg_data = &(config->lua_script);
	config_entries[i++].arg_data = &(config->users_file);

	return config_entries;
}

/**
 * init the plugin with the parsed config
 */
static int network_mysqld_admin_plugin_apply_config(chassis *chas, chassis_plugin_config *config) {
	network_mysqld_con *con;
	network_socket *listen_sock;

	if (!config->address) config->address = g_strdup(":4041");
	if (!config->admin_username) {
		g_critical("%s: --admin-username needs to be set",
				G_STRLOC);
		return -1;
	}
	if (!config->admin_password) {
		g_critical("%s: --admin-password needs to be set",
				G_STRLOC);
		return -1;
	}
	if (!config->lua_script) {
		g_critical("%s: --admin-lua-script needs to be set, <install-dir>/lib/mysql-proxy/lua/admin.lua may be a good value",
				G_STRLOC);
		return -1;
	}
    if (!config->users_file) {
		g_critical("%s: --admin-users-file needs to be set, <install-dir>/lib/mysql-proxy/proxy-user.cnf may be a good value",
				G_STRLOC);
		return -1;
	}

    if (admin_read_users_file(chas, config)) {
        return -1;
    }

	/** 
	 * create a connection handle for the listen socket 
	 */
	con = network_mysqld_con_new();
	network_mysqld_add_connection(chas, con);
	con->config = config;

	config->listen_con = con;
	
	listen_sock = network_socket_new();
	con->server = listen_sock;

	/* set the plugin hooks as we want to apply them to the new connections too later */
	network_mysqld_server_connection_init(con);

	/* FIXME: network_socket_set_address() */
	if (0 != network_address_set_address(listen_sock->dst, config->address)) {
		return -1;
	}

	/* FIXME: network_socket_bind() */
	if (0 != network_socket_bind(listen_sock)) {
		return -1;
	}

	/**
	 * call network_mysqld_con_accept() with this connection when we are done
	 */
	event_set(&(listen_sock->event), listen_sock->fd, EV_READ|EV_PERSIST, network_mysqld_con_accept, con);
	event_base_set(chas->event_base, &(listen_sock->event));
	event_add(&(listen_sock->event), NULL);

	return 0;
}

G_MODULE_EXPORT int plugin_init(chassis_plugin *p) {
	p->magic        = CHASSIS_PLUGIN_MAGIC;
	p->name         = g_strdup("admin");
	p->version		= g_strdup(PACKAGE_VERSION);

	p->init         = network_mysqld_admin_plugin_new;
	p->get_options  = network_mysqld_admin_plugin_get_options;
	p->apply_config = network_mysqld_admin_plugin_apply_config;
	p->destroy      = network_mysqld_admin_plugin_free;
    p->get_ini_str  = network_mysqld_admin_plugin_get_ini_str;      //add by vinchen/CFR

	return 0;
}


