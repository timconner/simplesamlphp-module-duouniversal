<?php

declare(strict_types=1);

namespace SimpleSAML\Module\duouniversal;

use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Logger;

use function implode;
use function is_null;

class Utils
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
    public static function resolveDuoAppConfig(
        Configuration $duoConfig,
        string $entityID
    ): ?array {
        $defaultDuoApp = $duoConfig->getValue('defaultDuoApp');
        $spDuoOverrides =  $duoConfig->getValue('spDuoOverrides');
        $alternateDuoApps = $duoConfig->getOptionalValue('alternateDuoApps', []);

        // A default app is required
        if (is_null($defaultDuoApp)) {
            Logger::error('module_duouniversal.php config missing defaultDuoApp');
            throw new ConfigurationError("Server configuration invalid.");
        }

        // No overrides configured or no override for this EntityID, return the default app config.
        $noOverridesSet = is_null($spDuoOverrides);
        $noOverrideForEntityID = !isset($spDuoOverrides[$entityID]);
        if ($noOverridesSet || $noOverrideForEntityID) {
            $resolvedConfig = $defaultDuoApp;
            $resolvedConfig['name'] = 'default';
            return self::validateDuoAppConfig($resolvedConfig, 'defaultDuoApp');
        }

        $overrideAppName = $spDuoOverrides[$entityID] ?? null;

        // If the override app name is 'bypass', return null to indicate this EntityID should bypass Duo.
        if ($overrideAppName == 'bypass') {
            return null;
        } else if (isset($alternateDuoApps[$overrideAppName])) {
            // There is an override app, return its configuration.
            $resolvedConfig = $alternateDuoApps[$overrideAppName];
            $resolvedConfig['name'] = $overrideAppName;
            return self::validateDuoAppConfig($resolvedConfig, $overrideAppName);
        } else {
            Logger::error('Undefined alternateDuoApp ' . $overrideAppName . ' for EntityID ' . $entityID);
            throw new ConfigurationError("Server configuration invalid.");
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
        $missing = [];
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
            Logger::error('Duo app config ' . $configName . ' missing attributes: ' . implode(',', $missing));
            throw new ConfigurationError('Server configuration invalid.');
        } else {
            return $duoAppConfig;
        }
    }
}
