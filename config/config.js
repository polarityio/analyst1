module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'Analyst1',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'A1',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: 'Analyst1 is a threat intelligence platform',
  entityTypes: ['IPv4', 'IPv6', 'domain', 'hash', 'email', 'cve'],
  customTypes: [
    {
      key: 'extendedEmail',
      // This regex does not prevent emails that start or end with a `.` or have consecutive `.` characters.
      // This regex captures emails that Analyst1 treats as valid and does not capture emails with escaped characters or
      // emails with the local part in quotes which are not supported by Analyst1.
      regex: /^[a-zA-Z0-9!#$%&'*+\-\/=?^_`{|}~.]{1,63}@[a-zA-Z0-9\-]{1,63}(\.[a-zA-Z]{2,63})+/
    }
  ],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  styles: ['./styles/styles.less'],
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
      description:
        'The base URL for the Analyst1 API to include the schema (https://) and port as needed.  This option should be set to "Users can view only".',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'userName',
      name: 'Email Address',
      description: 'Valid Analyst1 Email Address',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Password',
      description: 'Valid Analyst1 Password for the given email address',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'verifiedOnly',
      name: 'Verified Indicators Only',
      description:
        'If checked, the integration will only return verified indicators.  If this option is a per-user setting, the integration cache should be set to per user.',
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'enableEvidenceSubmission',
      name: 'Enable Evidence Submission',
      description:
        'If checked, the integration will allow users to submit text based evidence directly from the Overlay Window.',
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'defaultEvidenceTlp',
      name: 'Default Evidence TLP',
      description: 'The default TLP level for submitted evidence.',
      default: {
        value: 'undetermined',
        display: 'Undetermined'
      },
      type: 'select',
      options: [
        {
          value: 'undetermined',
          display: 'Undetermined'
        },
        {
          value: 'white',
          display: 'White'
        },
        {
          value: 'green',
          display: 'Green'
        },
        {
          value: 'amber',
          display: 'Amber'
        },
        {
          value: 'red',
          display: 'Red'
        }
      ],
      multiple: false,
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'evidenceSourceId',
      name: 'Evidence Source Id',
      description:
        'The numeric source identifier to be associated with submitted evidence.  We recommend creating a Polarity specific source under "Admin Controls" -> "Manage Sources". If left blank the Evidence Source with be set to unknown.',
      default: -1,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
