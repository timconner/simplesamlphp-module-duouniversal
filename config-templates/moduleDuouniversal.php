<?php

$config = array(
    // Default application to use for Duo authentication when an alternate Duo application is
    // not configured in SPEntityIdToDuo - required
    'defaultDuoApp' => array(
        'clientID' => '',               // Duo API Client ID
        'clientSecret' => '',           // Duo API Client Secret
        'apiHost' => '',                // Duo API hostname
        'usernameAttribute' => '',      // Attribute to use when contacting Duo
        // 'storePrefix' => '',         // Prefix for keys sent to the SimpleSAML store, optional.
    ),

    // List of applications to for spDuoOverrides
    'alternateDuoApps' => array(
        /*
        'strict' => array(
            'clientID' => '',
            'clientSecret' => '',
            'apiHost' => '',
            'usernameAttribute' => '',
            'storePrefix' => '',
        )
        */
    ),

    // Override the default Duo app per-SP EntityID.
    // EntityIDs listed here will use the configuration from the corresponding defined in
    // alternateDuoApps.
    // Set the value to 'bypass' for SP EntityIDs which should not prompt Duo.
    'spDuoOverrides' => array(
        //'https://example.com/sso/sp' => 'strict',

        // SPs associated with 'bypass' will not be prompted for Duo.
        //'https://example.com/some/other/sp' => 'bypass'
    ),
);