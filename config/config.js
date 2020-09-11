module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'Analyst1 Platform',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'AN1',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: 'Analyst1 is a threat intelligence platform',
  entityTypes: ['IPv4', 'IPv6', 'domain', 'hash', 'email', 'cve'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  styles: ['./styles/ill.less'],
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    // If set to false, the integration will ignore SSL errors.  This will allow the integration to connect
    // to servers without valid SSL certificates.  Please note that we do NOT recommending setting this
    // to false in a production environment.
    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'url',
      name: 'Analyst1 API URL',
      description: 'The base URL for the Analyst1 API to include the schema (https://) and port as needed',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'userName',
      name: 'User Name',
      description: 'Valid Analyst1 Username',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Password',
      description: 'Valid Analyst1 Password',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'doIndicatorMatchSearch',
      name: 'Match Indicator Values',
      description:
        'If checked, the integration will only return results for a matched indicator value.  If unchecked, a full text search will be run for the given indicator.  To prevent large amounts of false positives it is recommended to keep this option checked.',
      default: true,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
