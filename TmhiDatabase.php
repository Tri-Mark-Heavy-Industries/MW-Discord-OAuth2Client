<?php
require_once __DIR__.'/TmhiMember.php';

class TmhiDatabase {
    private $_conn;

    public function __construct($dbHost, $dbDatabase, $dbUser, $dbPassword) {
        // open the database using provided credentials
        $this->_conn = new PDO("mysql:host=$dbHost;dbname=$dbDatabase", $dbUser, $dbPassword);

        // set the PDO error mode to exception
        $this->_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Create, bind, execute and fetch a single result of a SQL query
     * @param string $sql The query to execute
     * @param string $params Parameters to bind
     * @param array A single result in a named array
     */
    private function _query($sql, $params) {
        $statement = $this->_conn->prepare($sql);
        $statement->execute($params);
        return $statement->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * Create, bind, execute and fetch all results of a SQL query
     * @param string $sql The query to execute
     * @param string $params Parameters to bind
     * @param array[] An array of results in named arrays
     */
    private function _queryAll($sql, $params) {
        $statement = $this->_conn->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Store a Discord member's access token
     * @param Snowflake $guildMember The member who owns the access token
     * @param League\OAuth2\Client\Token\AccessToken $accessToken The access token to store
     */
    public function storeAccessToken($discordId, $accessToken)    {
        $token        = $accessToken->getToken();
        $expires      = $accessToken->getExpires();
        $refreshToken = $accessToken->getRefreshToken();

        $this->_query('
            INSERT INTO members (id, discordtoken, discordtokenexpires, discordrefreshtoken)
            VALUES (:id, :token, :tokenexpires, :refreshtoken)
            ON DUPLICATE KEY
            UPDATE discordtoken=:token, discordtokenexpires=:tokenexpires, discordrefreshtoken=:refreshtoken
        ', [
            'id'           => $discordId,
            'token'        => $token,
            'tokenexpires' => $expires,
            'refreshtoken' => $refreshToken,
        ]);
    }

    /**
     * Store a T-MHI member
     * @param TmhiMember $tmhiMember The member to add
     */
    public function storeTmhiMember($tmhiMember) {
        $this->_query('
            UPDATE members
            SET wikiid=:wikiid, email=:email
            WHERE id=:discordid
        ', [
            'wikiid'    => $tmhiMember->wikiId,
            'email'     => $tmhiMember->email,
            'discordid' => $tmhiMember->discordId,
        ]);
    }
    
    /**
    * Retrieve a T-MHI member from the database
    * @param Snowflake $discordId The Discord Snowflake ID of the user
    * @return TmhiMember The requested member
    */
    public function loadTmhiMember($discordId) {
        // load user
        $row = $this->_query('
            SELECT displayname, wikiid, email, timezone
            FROM members
            WHERE id=:discordid
        ', [ 'discordid' => $discordId ]);

        // no user found
        if (!$row) {
            return false;
        }
        $displayName = $row['displayname'];
        $wikiid      = $row['wikiid'];
        $email       = $row['email'];
        $timezone    = $row['timezone'];

        // load roles for user
        $rows = $this->_queryAll('
            SELECT roles.id as id, roles.name as name, roles.comment as comment
            FROM memberroles
            JOIN roles ON memberroles.roleid=roles.id
            WHERE memberroles.userid=:discordid
        ', [ 'discordid' => $discordId ]);

        // map roles into an array
        $roles = [];
        foreach ($rows as $row) {
            $roles[$row['id']] = [
                'name'    => $row['name'],
                'comment' => $row['comment'],
            ];
        }

        // load permissions for user (if the user has at least one role)
        $permissions = [];
        if (count($roles)) {
            $rows = $this->_queryAll('
                SELECT permissions.id as id, permissions.name as name, permissions.comment as comment
                FROM rolepermissions
                JOIN permissions ON rolepermissions.permissionid=permissions.id
                WHERE rolepermissions.roleid IN (' . join(',', array_fill(0, count($roles), '?')) . ')
            ', array_keys($roles));
    
            // map permissions into an array
            foreach ($rows as $row) {
                $permissions[$row['id']] = [
                    'name'    => $row['name'],
                    'comment' => $row['comment'],
                ];
            }
        }

        return new TmhiMember(
            $discordId,
            $displayName,
            $permissions,
            $wikiid,
            $email,
            $timezone
        );
    }
}
