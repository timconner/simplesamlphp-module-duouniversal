<?php

use sspmod_duouniversal_Utils as DuUtils;

use Duo\DuoUniversal\DuoException;
use SimpleSAML\Auth;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception as SimpleSAMLException;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\saml\Error\NoPassive;
use SimpleSAML\Session;
use SimpleSAML\Store;
use SimpleSAML\Utils\HTTP;

/**
 * Duo Universal Authentication Processing filter
 *
 * Filter to redirect users to the Duo Universal prompt for two-factor authentication.
 *
 * @package simpleSAMLphp
 */
class sspmod_duouniversal_Auth_Process_Duouniversal extends SimpleSAML\Auth\ProcessingFilter
{

    private $moduleConfig;

    /**
     * Initialize Duo Universal
     *
     * Validates and parses the configuration
     *
     * @param array $config Configuration information
     * @param mixed $reserved
     * @throws \SimpleSAML\Error\Exception
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        // Fetch the store prefix and api information from the module config.
        $this->moduleConfig = SimpleSaml\Configuration::getConfig('moduleDuouniversal.php');
    }

    /**
     * Helper function to check whether Duo is disabled.
     *
     * @param mixed $option  The consent.disable option. Either an array or a boolean.
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
     * @throws \SimpleSAML\Error\BadRequest
     * @throws Duo\DuoUniversal\DuoException
     * @throws SimpleSAML\Module\saml\Error\NoPassive
     * @throws \SimpleSAML\Error\CriticalConfigurationError
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    public function process(&$state)
    {
        $spEntityId = $state['Destination']['entityid'];
        $idpEntityId = $state['Source']['entityid'];

        $metadata = MetaDataStorageHandler::getMetadataHandler();

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

        // User interaction with Duo is required, so we throw NoPassive on isPassive request.
        if (isset($state['isPassive']) && $state['isPassive'] == true) {
            throw new NoPassive('Unable to login with passive request.');
        }

        // Determine the correct Duo application to use and set configuration.
        $duoAppConfig = DuUtils::resolveDuoAppConfig($this->moduleConfig, $spEntityId);

        // Bypass Duo auth if the app config returned is null.
        if (is_null($duoAppConfig)) {
            Auth\ProcessingChain::resumeProcessing($state);
        }

        // Set up Duo client based on resolved app config
        $clientID = $duoAppConfig['clientID'];
        $clientSecret = $duoAppConfig['clientSecret'];
        $apiHost = $duoAppConfig['apiHost'];
        $usernameAttribute = $duoAppConfig['usernameAttribute'];
        $storePrefix = $this->moduleConfig->getValue('storePrefix') ?? "duouniversal";

        try {
            $duoClient = new Duo\DuoUniversal\Client(
                $clientID,
                $clientSecret,
                $apiHost,
                Module::getModuleURL('duouniversal/duocallback.php')
            );
        } catch (DuoException $ex) {
            throw new SimpleSAMLException('Duo configuration error: ' . $ex->getMessage());
        }

        // Fetch username for Duo from attributes based on configured username attribute.
        if (isset($state['Attributes'][$usernameAttribute][0])) {
            $username = $state['Attributes'][$usernameAttribute][0];
        }
        else {
            throw new BadRequest('Missing required username attribute.');
        }

        // Check if Duo API connection is functional, this will throw a DuoException to indicate failure.
        $duoClient->healthCheck();


        // Generate Duo state nonce and store in current SimpleSAML auth state.
        $duoNonce = $duoClient->generateState();
        $state['duouniversal:duoNonce'] = $duoNonce;

        // Save the current ssp state and get a state ID.
        $stateId = State::saveState($state, 'duouniversal:duoRedirect');

        // Get an instance of the SimpleSAML store
        $store = Store::getInstance();

        // Save the SimpleSAML state ID in the store under the Duo nonce generated earlier.
        $stateIDKey = $storePrefix . ':' . $duoNonce;
        $store->set('string', $stateIDKey, $stateId, time() + 300);

        // Build a Duo URL for this authentication and redirect.
        $promptUrl = $duoClient->createAuthUrl($username, $duoNonce);
        HTTP::redirectTrustedURL($promptUrl);
    }
}
