<?php

use Simplesaml\Configuration;
use SimpleSAML\Error\ConfigurationError;

class sspmod_duouniversal_Utils
{

    /**
     * Determines the correct Duo application configuration to use for a given EntityID. Returns the configuration
     * to use as an array or null if the authentication should bypass Duo.
     *
     * @param Configuration $duoConfig Duo module config as loaded by SimpleSaml\Configuration::getConfig()
     * @param string $entityID Entity ID to resolve an app config for
     * @return array|null
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public static function resolveDuoAppConfig(Configuration $duoConfig, string $entityID): ?array {
        $defaultDuoApp = $duoConfig->getValue('defaultDuoApp');
        $spDuoOverrides =  $duoConfig->getValue('spDuoOverrides');
        $alternateDuoApps = $duoConfig->getValue('alternateDuoApps');

        // A default app is required
        if (is_null($defaultDuoApp)) {
            throw new ConfigurationError('moduleDuouniversal.php config missing defaultDuoApp');
        }

        // No overrides configured or no override for this EntityID, return the default app config.
        $noOverridesSet = is_null($spDuoOverrides);
        $noOverrideForEntityID = !isset($spDuoOverrides[$entityID]);
        if ($noOverridesSet || $noOverrideForEntityID) {
            return sspmod_duouniversal_Utils::validateDuoAppConfig($defaultDuoApp, 'defaultDuoApp');
        }

        $overrideAppName = $spDuoOverrides[$entityID];

        // If the override app name is 'bypass', return null to indicate this EntityID should bypass Duo.
        if ($overrideAppName == 'bypass') {
            return null;
        } else if (isset($alternateDuoApps[$overrideAppName])) {
            // There is an override app, return its configuration.
            return  sspmod_duouniversal_Utils::validateDuoAppConfig($alternateDuoApps[$overrideAppName],
                                                                    $overrideAppName);
        } else {
            // Fall back to the default as to not fail open.
            return sspmod_duouniversal_Utils::validateDuoAppConfig($defaultDuoApp, 'defaultDuoApp');
        }
    }

    /**
     * Validates the required elements are in a given Duo app config array. Returns the config if valid
     * or throws a ConfigurationError.
     *
     * @param array $duoAppConfig The configuration for the Duo app in question
     * @param string $configName The name of the configuration for error messaging
     * @return array
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    private static function validateDuoAppConfig(array $duoAppConfig, string $configName = ''): array
    {
        $missing = array();
        if (!isset($duoAppConfig['clientID']) || $duoAppConfig['clientID'] == '') {
            $missing[] = 'clientID';
        }

        if (!isset($duoAppConfig['clientSecret']) || $duoAppConfig['clientSecret'] == '') {
           $missing[] = 'clientSecret';
        }
        if (!isset($duoAppConfig['apiHost']) || $duoAppConfig['apiHost'] == '') {
            $missing[] = 'apiHost';
        }
        if (!isset($duoAppConfig['usernameAttribute']) || $duoAppConfig['usernameAttribute'] == '') {
            $missing[] = 'usernameAttribute';
        }

        if (!empty($missing)) {
            $m = 'Duo app config ' . $configName . ' missing attributes: ' . implode(',', $missing);
            throw new ConfigurationError($m);
        } else {
            return $duoAppConfig;
        }
    }
}