<?php
/**
 * Users are redirected to this page after Duo authentication via the Universal Prompt.
 *
 * @package simpleSAMLphp
 */

use sspmod_duouniversal_Utils as DuUtils;

use Duo\DuoUniversal\DuoException;
use SimpleSAML\Auth;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Error\Exception as SimpleSAMLException;
use SimpleSAML\Module;

// Signal to clients/proxies to not cache this page.
session_cache_limiter('nocache');

// Check for Duo errors in callback
if (isset($_GET['error'])) {
    $duoError = $_GET['error'] . ':' . $_GET['error_description'];
    throw new BadRequest('Error response from Duo during authentication: ' . $duoError);
}

// Ensure we got back a Duo code and state nonce
if (!isset($_GET['duo_code']) || !isset($_GET['state'])) {
    throw new BadRequest('Invalid response from Duo');
}

// Get the returned code and nonce from the Duo authentication redirect.
$duoCode = $_GET['duo_code'];
$duoNonce = $_GET['state'];

// Load module configuration and get storePrefix to start
$moduleConfig = SimpleSaml\Configuration::getConfig("module_duouniversal.php");
$duoStorePrefix = $moduleConfig->getValue('storePrefix', 'duouniversal');

// Bootstrap authentication state by retrieving an SSP state ID using the Duo nonce provided by the
// Duo authentication redirect.
try {
    $store = SimpleSAML\Store::getInstance();
    $stateID = $store->get('string', $duoStorePrefix . ':'. $duoNonce);
} catch (Exception $ex) {
    throw new SimpleSAMLException('Failure loading SimpleSAML state');
}

// If the duo nonce isn't associated with an SSP state ID, the auth is invalid.
if (!isset($stateID) ){
    throw new SimpleSAMLException('No state with Duo nonce ' . $duoNonce);
}

// Fetch the state using the retrieved SSP state ID.
$state = Auth\State::loadState($stateID, 'duouniversal:duoRedirect');
if (!isset($state)) {
    // If loadState doesn't find a state, it returns null, so we have to check and throw our own exception.
    throw new SimpleSAMLException('No state with Duo nonce ' . $duoNonce);
}

// Check that the retrieved state has an associated Duo nonce.
if (!isset($state['duouniversal:duoNonce'])) {
    throw new SimpleSAMLException('Retrieved state is missing Duo nonce');
}

// Double-check that the Duo nonce saved in the retrieved state matches the one we've retrieved from the
// associated simplesamlphp auth state.
if ($state['duouniversal:duoNonce'] != $duoNonce) {
    $m = 'Duo nonce ' . $duoNonce . ' does not match nonce ' . $state['duouniversal:duoNonce']. 'from retrieved state.';
    throw new SimpleSAMLException($m);
}

// Now that we have a valid state we can get the SP Entity ID to resolve an override app config, if any.
$duoAppConfig = DuUtils::resolveDuoAppConfig($moduleConfig, $state['Destination']['entityid']);

if (is_null($duoAppConfig)) {
    // This should never happen in this script, fail closed.
    throw new ConfigurationError("Duo Callback received for bypassed EntityID.");
}

$clientID = $duoAppConfig['clientID'];
$clientSecret = $duoAppConfig['clientSecret'];
$apiHost = $duoAppConfig['apiHost'];
$usernameAttribute = $duoAppConfig['usernameAttribute'];

// Set up a new Duo Client for validating the returned Duo code.
try {
    $duoClient = new Duo\DuoUniversal\Client(
        $clientID,
        $clientSecret,
        $apiHost,
        Module::getModuleURL('duouniversal/duocallback.php')
    );
} catch (DuoException $ex) {
    throw new ConfigurationError('Duo configuration error: ' . $ex->getMessage());
}

// Call Duo API and check token.
try {
    $decodedToken = $duoClient->exchangeAuthorizationCodeFor2FAResult($duoCode, $state['Attributes'][$usernameAttribute][0]);
} catch (DuoException $ex ) {
    throw new BadRequest("Error decoding Duo result: " . $ex);
}

// If nothing has gone wrong, resume processing.
Auth\ProcessingChain::resumeProcessing($state);