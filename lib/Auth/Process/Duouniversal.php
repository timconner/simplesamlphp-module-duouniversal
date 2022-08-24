<?php
/**
 * Duo Universal Authentication Processing filter
 *
 * Filter to present Duo two factor authentication form
 *
 * @package simpleSAMLphp
 */
class sspmod_duouniversal_Auth_Process_Duouniversal extends SimpleSAML\Auth\ProcessingFilter
{

    /**
     * Include attribute values
     *
     * @var bool
     */
    private $_includeValues = false;

    private $_duoComplete = null;

    private $_akey;

    private $_ikey;

    private $_skey;

    private $_host;

    private $_authSources = 'all';

    private $_usernameAttribute = 'username';

    private $_duoClient = null;

    private $_storePrefix = 'duouniversal:';

    /**
     * Initialize Duo Universal
     *
     * Validates and parses the configuration
     *
     * @param array $config   Configuration information
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        // Fetch the store prefix and api information from the module config.
        $duoConfig = SimpleSaml\Configuration::getConfig('moduleDuouniversal.php');
        $this->_storePrefix = $duoConfig->getValue('storePrefix', 'duouniversal');

        $this->_host = $duoConfig->getValue('host');
        $this->_ikey = $duoConfig->getValue('ikey');
        $this->_skey = $duoConfig->getValue('skey');
        $this->_usernameAttribute = $duoConfig->getValue('usernameAttribute');

        try {
            $this->_duoClient = new Duo\DuoUniversal\Client(
                $this->_ikey,
                $this->_skey,
                $this->_host,
                \SimpleSAML\Module::getModuleURL('duouniversal/duocallback.php')
            );
        } catch (\Duo\DuoUniversal\DuoException $ex) {
            throw new \SimpleSAML\Error\Exception('Duo configuration error: ' . $ex->getMessage());
        }
    }

    /**
     * Helper function to check whether Duo is disabled.
     *
     * @param mixed $option  The consent.disable option. Either an array or a boolean.
     * @param string $entityIdD  The entityID of the SP/IdP.
     * @return boolean  TRUE if disabled, FALSE if not.
     */
    private static function checkDisable($option, $entityId) {
        if (is_array($option)) {
            return in_array($entityId, $option, TRUE);
        } else {
            return (boolean)$option;
        }
    }

    /**
     * Process an authentication response
     *
     * This function saves the state, and redirects the user to the page where
     * the user can log in with their second factor.
     *
     * @param array &$state The state of the response.
     *
     * @return void
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Destination", $state)');
        assert('array_key_exists("entityid", $state["Destination"])');
        assert('array_key_exists("metadata-set", $state["Destination"])');
        assert('array_key_exists("Source", $state)');
        assert('array_key_exists("entityid", $state["Source"])');
        assert('array_key_exists("metadata-set", $state["Source"])');

        $spEntityId = $state['Destination']['entityid'];
        $idpEntityId = $state['Source']['entityid'];

        $metadata = SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();

        /**
         * If the Duo Universal module is active on a bridge $state['saml:sp:IdP']
         * will contain an entry id for the remote IdP. If not, then
         * it is active on a local IdP and nothing needs to be
         * done.
         */
        if (isset($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpmeta         = $metadata->getMetaData($idpEntityId, 'saml20-idp-remote');
            $state['Source'] = $idpmeta;
        }

        // Get idP session from auth request
        $session = SimpleSAML\Session::getSessionFromRequest();

        // Has user already passed DUO authorization in this idP session instance?
        $isAuthorized = $session->getData('duouniversal:request', 'is_authorized');

        // Bypass DUO if already authenticated with the idP and DUO
        if (isset($state['AuthnInstant']) && $isAuthorized) {
            return;
        }

        $session->setData('duouniversal:request', 'is_authorized', false);

        // User interaction necessary. Throw exception on isPassive request
        if (isset($state['isPassive']) && $state['isPassive'] == true) {
            throw new SimpleSAML\Module\saml\Error\NoPassive(
                'Unable to login with passive request.'
            );
        }

        //
        if (isset($state['Attributes'][$this->_usernameAttribute][0])) {
            $username = $state['Attributes'][$this->_usernameAttribute][0];
        }
        else {
            throw new SimpleSAML\Error\BadRequest('Missing required username attribute.');
        }

        try {
            $this->_duoClient->healthCheck();
        } catch (\Duo\DuoUniversal\DuoException $ex) {

        }

        # Generate Duo state nonce and store in current SimplesspSAML auth state.
        $duoNonce = $this->_duoClient->generateState();
        $state['duouniversal:duoNonce'] = $duoNonce;

        # Save the current ssp state and get the state ID.
        $stateId = \SimpleSAML\Auth\State::saveState($state, 'duouniversal:duoRedirect');

        # Get an instance of the SimpleSAML store
        $store = SimpleSAML\Store::getInstance();

        # Save the state ID in the store under Duo nonce generated earlier.
        $state_id_key = $this->_storePrefix . ':' . $duoNonce;
        $store->set('string', $state_id_key, $stateId, time() + 300);
        $promptUrl = $this->_duoClient->createAuthUrl($username, $duoNonce);
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($promptUrl);
    }
}
