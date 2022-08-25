<?php
/**
 * Users are redirected to this page after Duo authentication via the Universal Prompt.
 *
 * @package simpleSAMLphp
 */

use Duo\DuoUniversal\DuoException;
use SimpleSAML\Auth;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Error\Exception as SimpleSAMLException;
use SimpleSAML\Module;

session_cache_limiter('nocache');

// Check for Duo errors in callback
if (isset($_GET['error'])) {
    $error_msg = $_GET['error'] . ':' . $_GET['error_description'];
    throw new BadRequest('Error response from Duo during authentication: ' . $error_msg);
}

// Ensure we got back a Duo code and state nonce
if (!isset($_GET['duo_code']) || !isset($_GET['state'])) {
    throw new BadRequest('Invalid response from Duo');
}

$duoCode = $_GET['duo_code'];
$duoNonce = $_GET['state'];

// Bootstrap config and state information for interacting with Duo to deal with callback redirect.
// Fetch duo  information from the module config.
$duoConfig = SimpleSaml\Configuration::getConfig("moduleDuouniversal.php");
$duoStorePrefix = $duoConfig->getValue('storePrefix', 'duouniversal');

$host = $duoConfig->getValue('host');
$ikey = $duoConfig->getValue('ikey');
$skey = $duoConfig->getValue('skey');
$usernameAttribute = $duoConfig->getValue('usernameAttribute');

try {
    $duoClient = new Duo\DuoUniversal\Client(
        $ikey,
        $skey,
        $host,
        Module::getModuleURL('duouniversal/duocallback.php')
    );
} catch (DuoException $ex) {
    throw new ConfigurationError('Duo configuration error: ' . $ex->getMessage());
}

// Try retrieving an SSP state ID with the provided Duo nonce.
try {
    $store = SimpleSAML\Store::getInstance();
    $stateId = $store->get('string', $duoStorePrefix . ':'. $duoNonce);
} catch (Exception $ex) {
    throw new SimpleSAMLException('Failure loading SimpleSAML state');
}
// If the duo nonce isn't associated with an SSP state ID, the auth is invalid.
if (!isset($stateId) ){
    throw new SimpleSAMLException('No state with Duo nonce ' . $duoNonce);
}
$state = Auth\State::loadState($stateId, 'duouniversal:duoRedirect');
if (!isset($state)) {
    throw new SimpleSAMLException('No state with Duo nonce ' . $duoNonce);
}
if (!isset($state['duouniversal:duoNonce'])) {
    throw new SimpleSAMLException('Retrieved state is missing Duo nonce');
}

// Double-check that the Duo nonce saved in the retrieved state matches the one we've retrieved from the
// associated simplesamlphp auth state.
if ($state['duouniversal:duoNonce'] != $duoNonce) {
    $m = 'Duo nonce ' . $duoNonce . ' does not match nonce ' . $state['duouniversal:duoNonce']. 'from retrieved state.';
    throw new SimpleSAMLException($m);
}

// Call Duo API and check token.
try {
    $decodedToken = $duoClient->exchangeAuthorizationCodeFor2FAResult($duoCode, $state['Attributes'][$usernameAttribute][0]);
} catch (DuoException $ex ) {
    throw new BadRequest("Error decoding Duo result: " . $ex);
}

// If nothing has gone wrong, resume processing.
Auth\ProcessingChain::resumeProcessing($state);