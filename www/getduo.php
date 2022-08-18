<?php
/**
 * Duo Security script
 *
 * This script displays a page to the user for two factor authentication
 *
 * @package simpleSAMLphp
 */
/**
 * In a vanilla apache-php installation is the php variables set to:
 *
 * session.cache_limiter = nocache
 *
 * so this is just to make sure.
 */
session_cache_limiter('nocache');

$globalConfig = SimpleSAML\Configuration::getInstance();

SimpleSAML\Logger::info('Duo Universal - getduo: Accessing Duo interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML\Error\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];

// sanitize the input
$sid = \SimpleSAML\Auth\State::parseStateID($id);
if (!is_null($sid['url'])) {
    \SimpleSAML\Utils\HTTP::checkURLAllowed($sid['url']);
}

$state = SimpleSAML\Auth\State::loadState($id, 'duouniversal:request');

if (array_key_exists('core:SP', $state)) {
    $spentityid = $state['core:SP'];
} else if (array_key_exists('saml:sp:State', $state)) {
    $spentityid = $state['saml:sp:State']['core:SP'];
} else {
    $spentityid = 'UNKNOWN';
}

// Duo returned a good auth, pass the user on
if(isset($_POST['sig_response'])){
    require(SimpleSAML\Module::getModuleDir('duouniversal') . '/templates/duo_web.php');
    $resp = Duo::verifyResponse(
        $state['duouniversal:ikey'],
        $state['duouniversal:skey'],
        $state['duouniversal:akey'],
        $_POST['sig_response']
    );

    if (isset($state['Attributes'][$state['duouniversal:usernameAttribute']])) {
        $username = $state['Attributes'][$state['duouniversal:usernameAttribute']][0];
    }
    else {
        throw new SimpleSAML\Error\BadRequest('Missing required username attribute.');
    }

    if ($resp != NULL and $resp === $username) {
        // Get idP session from auth request
        $session = SimpleSAML\Session::getSessionFromRequest();

        // Set session variable that DUO authorization has passed
        $session->setData('duouniversal:request', 'is_authorized', true, SimpleSAML\Session::DATA_TIMEOUT_SESSION_END);

        SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
    }
    else {
        throw new SimpleSAML\Error\BadRequest('Response verification failed.');
    }
}

// Prepare attributes for presentation
$attributes = $state['Attributes'];
$para = array(
    'attributes' => &$attributes
);

// Make, populate and layout Duo form
$t = new SimpleSAML\XHTML\Template($globalConfig, 'duouniversal:duoform.php');
$t->data['akey'] = $state['duouniversal:akey'];
$t->data['ikey'] = $state['duouniversal:ikey'];
$t->data['skey'] = $state['duouniversal:skey'];
$t->data['host'] = $state['duouniversal:host'];
$t->data['usernameAttribute'] = $state['duouniversal:usernameAttribute'];
$t->data['srcMetadata'] = $state['Source'];
$t->data['dstMetadata'] = $state['Destination'];
$t->data['yesTarget'] = SimpleSAML\Module::getModuleURL('duouniversal/getduo.php');
$t->data['yesData'] = array('StateId' => $id);
$t->data['attributes'] = $attributes;

$t->show();
