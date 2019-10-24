<?php

class DiscordUser {
    private $_discordId;
    private $_displayName;
    private $_permissions;
    private $_wikiId;
    private $_email;

    public const TMHI_MEMBER  = 1 << 0;
    public const TMHI_ADMIN   = 1 << 1;
    public const WIKI_ACCOUNT = 1 << 2;

    public function __construct($discordId, $displayName, $permissions = 0, $wikiId = 0, $email = '') {
        $this->_discordId   = $discordId;
        $this->_displayName = $displayName;
        $this->_permissions = $permissions;
        $this->_wikiId      = $wikiId;
    }
    
    public function getPermission($permission) {
        return (bool) ($this->_permissions & $permission);
    }

	public function isTmhiMember() {
        return $this->getPermission(DiscordUser::TMHI_MEMBER);
    }

	public function hasWikiAccess() {
        return $this->getPermission(DiscordUser::WIKI_ACCOUNT);
    }

	public function getDiscordId() {
        return $this->_discordId;
    }

	public function getWikiId()	{
        return $this->_wikiId;
    }

	public function setWikiId($wikiId) {
        $this->_wikiId = $wikiId;
    }

	public function getEmail() {
        return $this->_email;
    }

	public function setEmail($email) {
        $this->_email = $email;
    }

	public function getDisplayName() {
        return $this->_displayName;
    }
}
