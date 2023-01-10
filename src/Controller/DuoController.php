<?php

declare(strict_types=1);

namespace SimpleSAML\Module\DuoUniversal\Controller;

use Duo\DuoUniversal\DuoException;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
//use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\DuoUniversal\Utils as DuUtils;
use SimpleSAML\Store\StoreFactory;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the duouniversal module.
 *
 * This class serves the different views available in the module.
 *
 * Users are redirected to this page after Duo authentication via the Universal Prompt.
 */
class DuoController
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request The current request.
     *
     */
    public function main(Request $request)
    {
        // Signal to clients/proxies to not cache this page.
        session_cache_limiter('nocache');
        Logger::debug('Processing Duo callback...');

        // Check for Duo errors in callback
        if (isset($_GET['error'])) {
            $duoError = $_GET['error'] . ':' . $_GET['error_description'];
            $m = 'Error response from Duo in callback';
            Logger::error($m . ': ' . $duoError);
            throw new Error\BadRequest($m);
        }

        // Ensure we got back a Duo code and state nonce
        if (!isset($_GET['duo_code']) || !isset($_GET['state'])) {
            $m = 'Invalid Duo callback, code or state missing.';
            Logger::error($m);
            throw new Error\BadRequest($m);
        }

        // Get the returned code and nonce from the Duo authentication redirect.
        $duoCode = $_GET['duo_code'];
        $duoNonce = $_GET['state'];

        Logger::debug('Duo callback appears valid, retrieving associated state.');

        // Load module configuration and get storePrefix to start
        $moduleConfig = Configuration::getConfig("module_duouniversal.php");
        $duoStorePrefix = $moduleConfig->getValue('storePrefix', 'duouniversal');

        // Bootstrap authentication state by retrieving an SSP state ID using the Duo nonce provided by the
        // Duo authentication redirect.
        try {
            $store = StoreFactory::getInstance();
            $stateID = $store->get('string', $duoStorePrefix . ':'. $duoNonce);
        } catch (Exception $ex) {
            $m = 'Failed to load SimpleSAML state with nonce.';
            Logger::error('Nonce: ' . $duoNonce . '; ' . $m);
            throw new Error\Exception($m);
        }

        // If the duo nonce isn't associated with an SSP state ID, the auth is invalid.
        if (!isset($stateID) ){
            $m = 'No state with Duo nonce.';
            Logger::error('Nonce: ' . $duoNonce. '; '. $m);
             throw new Error\Exception($m);
        }

        // Fetch the state using the retrieved SSP state ID.
        $state = Auth\State::loadState($stateID, 'duouniversal:duoRedirect');
        if (!isset($state)) {
            // If loadState doesn't find a state, it returns null, so we have to check and throw our own exception.
            $m = 'No state with Duo nonce.';
            Logger::error('Nonce: ' . $duoNonce. ';' . $m);
            throw new Error\Exception($m);
        }

        // Check that the retrieved state has an associated Duo nonce.
        if (!isset($state['duouniversal:duoNonce'])) {
            $m = 'Retrieved state missing Duo nonce.';
            Logger::error('Nonce: ' . $duoNonce . " State: " . $stateID . '; ' . $m);
            throw new Error\Exception($m);
        }

        // Double-check that the Duo nonce saved in the retrieved state matches the one we've retrieved from the
        // associated simplesamlphp auth state.
        if ($state['duouniversal:duoNonce'] != $duoNonce) {
            $m = 'Nonce: ' . $duoNonce . " State: " . $stateID . '; Nonce from retrieved state does not match callback nonce';
            Logger::error($m);
            throw new Error\Exception($m);
        }

        // Now that we have a valid state we can get the SP Entity ID to resolve an override app config, if any.
        $duoAppConfig = DuUtils::resolveDuoAppConfig($moduleConfig, $state['Destination']['entityid']);

        if (is_null($duoAppConfig)) {
            // This should never happen in this script, fail closed.
            $m = "Duo callback retrieved for bypassed EntityID.";
            Logger::critical('Nonce: ' . $duoNonce . " State: " . $stateID . '; ' . $m);
            throw new Error\ConfigurationError($m);
        }

        $clientID = $duoAppConfig['clientID'];
        $clientSecret = $duoAppConfig['clientSecret'];
        $apiHost = $duoAppConfig['apiHost'];
        $usernameAttribute = $duoAppConfig['usernameAttribute'];
        $duoAppName = $duoAppConfig['name'];

        Logger::debug('Validating Duo response with app config ' . $duoAppName);

        // Set up a new Duo Client for validating the returned Duo code.
        try {
            $duoClient = new Duo\DuoUniversal\Client(
                $clientID,
                $clientSecret,
                $apiHost,
                Module::getModuleURL('duouniversal/duocallback')
            );
        } catch (DuoException $ex) {
            $m = 'Error instantiating Duo client';
             Logger::error($m . " " . $ex->getMessage());
            throw new Error\Exception($m);
        }

        // Call Duo API and check token.
        try {
            $decodedToken = $duoClient->exchangeAuthorizationCodeFor2FAResult(
                $duoCode,
                $state['Attributes'][$usernameAttribute][0]
            );
        } catch (DuoException $ex ) {
            $m = "Error decoding duo result.";
            Logger::error($m . ' ' . $ex->getMessage());
            throw new Error\BadRequest($m);
        }
        Logger::debug('Duo verification successful, continuing authentication.');

        // If nothing has gone wrong, resume processing.
        Auth\ProcessingChain::resumeProcessing($state);
    }
}
