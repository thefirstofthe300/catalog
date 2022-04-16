{{/* Define the configs */}}
{{- define "synapse.config" -}}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: synapse-config
  labels:
  {{ include "common.labels" . | nindent 4 }}
  annotations:
    rollme: {{ randAlphaNum 5 | quote }}
data:
  homeserver.yaml: |
    server_name: {{ .Values.matrix.serverName }}
    pid_file: /data/homeserver.pid
    public_baseurl: {{ include "matrix.baseUrl" . | quote }}
    use_presence: {{ .Values.matrix.presence }}

    allow_public_rooms_over_federation: {{ and .Values.matrix.federation.enabled .Values.matrix.federation.allowPublicRooms }}

    block_non_admin_invites: {{ .Values.matrix.blockNonAdminInvites }}

    enable_search: {{ .Values.matrix.search }}

    {{- if .Values.matrix.federation.whitelist }}
    federation_domain_whitelist:
        {{- range .Values.matrix.federation.whitelist }}
        - {{ . }}
        {{- end }}
    {{- end}}

    federation_ip_range_blacklist:
    {{- range .Values.matrix.federation.blacklist }}
        - {{ . }}
    {{- end }}

    listeners:
      - port: 8008
        tls: false
        type: http
        x_forwarded: true
        bind_addresses: ['0.0.0.0']
        resources:
          - names: [client, federation]
            compress: false

    {{- if .Values.synapse.metrics.enabled }}
      - type: metrics
        port: {{ .Values.synapse.metrics.port }}
        bind_addresses: ['0.0.0.0']
        resources:
          - names: [metrics]
    {{- end }}

    admin_contact: 'mailto:{{ .Values.matrix.adminEmail }}'
    hs_disabled: {{ .Values.matrix.disabled }}
    hs_disabled_message: {{ .Values.matrix.disabledMessage }}
    redaction_retention_period: {{ .Values.matrix.retentionPeriod }}

    log_config: "/data/{{ .Values.matrix.serverName }}.log.config"
    media_store_path: "/data/media_store"
    uploads_path: "/data/uploads"
    max_upload_size: {{ .Values.matrix.uploads.maxSize }}
    max_image_pixels: {{ .Values.matrix.uploads.maxPixels }}
    url_preview_enabled: {{ .Values.matrix.urlPreviews.enabled }}

    {{- if .Values.coturn.enabled -}}
    {{- if not (empty .Values.coturn.uris) }}
    turn_uris:
        {{- range .Values.coturn.uris }}
        - {{ . }}
        {{- end }}
    {{- else }}
    turn_uris:
      - "turn:{{ include "matrix.hostname" . }}?transport=udp"
    {{- end }}
    turn_user_lifetime: 1h
    turn_allow_guests: {{ .Values.coturn.allowGuests }}
    {{- end }}

    enable_registration: {{ .Values.matrix.registration.enabled }}

    allow_guest_access: {{ .Values.matrix.registration.allowGuests }}

    {{- if .Values.synapse.metrics.enabled }}
    enable_metrics: true
    {{- end }}

    report_stats: false

    {{- if .Values.synapse.appConfig }}
    app_service_config_files:
    {{- range .Values.synapse.appConfig }}
      - {{ . }}
    {{- end }}
    {{- end }}

    signing_key_path: "/data/keys/{{ .Values.matrix.serverName }}.signing.key"

    {{- if .Values.matrix.security.trustedKeyServers }}
    trusted_key_servers:
        {{- range .Values.matrix.security.trustedKeyServers }}
        - server_name: {{ .serverName }}
          {{- if .verifyKeys }}
          verify_keys:
            {{- range .verifyKeys }}
              {{ .id | quote }}: {{ .key | quote }}
            {{- end }}
          {{- end }}
          {{- if .acceptKeysInsecurely }}
          accept_keys_insecurely: {{ .acceptKeysInsecurely }}
          {{- end }}
        {{- end }}
    {{- end }}

    suppress_key_server_warning: {{ .Values.matrix.security.supressKeyServerWarning }}
  {{- if not .Values.loadCustomConfig }}
  custom.yaml: |
    # PLACEHOLDER
  {{- end }}

  {{ .Values.matrix.serverName }}.log.config: |
    version: 1

    formatters:
      precise:
        format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s'

    filters:
      context:
        (): synapse.util.logcontext.LoggingContextFilter
        request: ""

    handlers:
      console:
        class: logging.StreamHandler
        formatter: precise
        filters: [context]

    loggers:
      synapse:
        level: {{ .Values.matrix.logging.synapseLogLevel }}

      synapse.storage.SQL:
        # beware: increasing this to DEBUG will make synapse log sensitive
        # information such as access tokens.
        level: {{ .Values.matrix.logging.sqlLogLevel }}


    root:
      level: {{ .Values.matrix.logging.rootLogLevel }}
      handlers: [console]
{{- if .Values.appServices.signal.enabled }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-bridge-signal
  labels:
  {{ include "common.labels" . | nindent 4 }}
  annotations:
    rollme: {{ randAlphaNum 5 | quote }}
data:
  config.yaml: |
    # Homeserver details
    homeserver:
      # The address that this appservice can use to connect to the homeserver.
      address: {{ .Release.Name }}.{{ .Release.Namespace }}
      # The domain of the homeserver (for MXIDs, etc).
      domain: {{ include "matrix.hostname" . }}
      # Whether or not to verify the SSL certificate of the homeserver.
      # Only applies if address starts with https://
      verify_ssl: false
      asmux: false
      # Number of retries for all HTTP requests if the homeserver isn't reachable.
      http_retry_count: 4
      # The URL to push real-time bridge status to.
      # If set, the bridge will make POST requests to this URL whenever a user's Signal connection state changes.
      # The bridge will use the appservice as_token to authorize requests.
      status_endpoint: null
      # Endpoint for reporting per-message status.
      message_send_checkpoint_endpoint: null
      # Maximum number of simultaneous HTTP connections to the homeserver.
      connection_limit: 100
      # Whether asynchronous uploads via MSC2246 should be enabled for media.
      # Requires a media repo that supports MSC2246.
      async_media: false

    # Application service host/registration related details
    # Changing these values requires regeneration of the registration.
    appservice:
      # The address that the homeserver can use to connect to this appservice.
      address: http://{{- printf "%v-%v" .Release.Name "signal" -}}.{{ .Release.Namespace }}:{{ .Values.service.signal.ports.signal.port }}
      # When using https:// the TLS certificate and key files for the address.
      tls_cert: false
      tls_key: false

      # The hostname and port where this appservice should listen.
      hostname: 0.0.0.0
      port: {{ .Values.service.signal.ports.signal.port }}
      # The maximum body size of appservice API requests (from the homeserver) in mebibytes
      # Usually 1 is enough, but on high-traffic bridges you might need to increase this to avoid 413s
      max_body_size: 1

      # The full URI to the database. SQLite and Postgres are supported.
      # However, SQLite support is extremely experimental and should not be used.
      # Format examples:
      #   SQLite:   sqlite:///filename.db
      #   Postgres: postgres://username:password@hostname/dbname
      database: {{ printf "postgres://%v@%v-%v/%v" .Values.postgresql.postgresqlUsername .Release.Name "postgresql" "matrix_bridge_signal" }}
      # Additional arguments for asyncpg.create_pool() or sqlite3.connect()
      # https://magicstack.github.io/asyncpg/current/api/index.html#asyncpg.pool.create_pool
      # https://docs.python.org/3/library/sqlite3.html#sqlite3.connect
      # For sqlite, min_size is used as the connection thread pool size and max_size is ignored.
      database_opts:
        min_size: 5
        max_size: 10

      # The unique ID of this appservice.
      id: signal
      # Username of the appservice bot.
      bot_username: signalbot
      # Display name and avatar for bot. Set to "remove" to remove display name/avatar, leave empty
      # to leave display name/avatar as-is.
      bot_displayname: Signal bridge bot
      bot_avatar: mxc://maunium.net/wPJgTQbZOtpBFmDNkiNEMDUp

      # Whether or not to receive ephemeral events via appservice transactions.
      # Requires MSC2409 support (i.e. Synapse 1.22+).
      # You should disable bridge -> sync_with_custom_puppets when this is enabled.
      ephemeral_events: true

      # Authentication tokens for AS <-> HS communication. Autogenerated; do not modify.
      as_token: "{{ derivePassword 1 "as_token" (include "matrix.hostname" .) "values" .Values.appServices.signal.tokenSalt }}"
      hs_token: "{{ derivePassword 1 "hs_token" (include "matrix.hostname" .) "values" .Values.appServices.signal.tokenSalt }}"

    # Prometheus telemetry config. Requires prometheus-client to be installed.
    metrics:
      enabled: false
      listen_port: 8000

    # Manhole config.
    manhole:
      # Whether or not opening the manhole is allowed.
      enabled: false
      # The path for the unix socket.
      path: /var/tmp/mautrix-signal.manhole
      # The list of UIDs who can be added to the whitelist.
      # If empty, any UIDs can be specified in the open-manhole command.
      whitelist:
      - 0

    signal:
      # Path to signald unix socket
      socket_path: /var/run/signald/signald.sock
      # Directory for temp files when sending files to Signal. This should be an
      # absolute path that signald can read. For attachments in the other direction,
      # make sure signald is configured to use an absolute path as the data directory.
      outgoing_attachment_dir: /tmp
      # Directory where signald stores avatars for groups.
      avatar_dir: ~/.config/signald/avatars
      # Directory where signald stores auth data. Used to delete data when logging out.
      data_dir: ~/.config/signald/data
      # Whether or not unknown signald accounts should be deleted when the bridge is started.
      # When this is enabled, any UserInUse errors should be resolved by restarting the bridge.
      delete_unknown_accounts_on_start: false
      # Whether or not message attachments should be removed from disk after they're bridged.
      remove_file_after_handling: true
      # Whether or not users can register a primary device
      registration_enabled: true
      # Whether or not to enable disappearing messages in groups. If enabled, then the expiration
      # time of the messages will be determined by the first users to read the message, rather
      # than individually. If the bridge has a single user, this can be turned on safely.
      enable_disappearing_messages_in_groups: false

    # Bridge config
    bridge:
      # Localpart template of MXIDs for Signal users.
      # {userid} is replaced with an identifier for the Signal user.
      username_template: "signal_{userid}"
      # Displayname template for Signal users.
      # {displayname} is replaced with the displayname of the Signal user, which is the first
      # available variable in displayname_preference. The variables in displayname_preference
      # can also be used here directly.
      displayname_template: "{displayname} (Signal)"
      # Whether or not contact list displaynames should be used.
      # Possible values: disallow, allow, prefer
      #
      # Multi-user instances are recommended to disallow contact list names, as otherwise there can
      # be conflicts between names from different users' contact lists.
      contact_list_names: disallow
      # Available variables: full_name, first_name, last_name, phone, uuid
      displayname_preference:
      - full_name
      - phone

      # Whether or not to create portals for all groups on login/connect.
      autocreate_group_portal: true
      # Whether or not to create portals for all contacts on login/connect.
      autocreate_contact_portal: false
      # Whether or not to use /sync to get read receipts and typing notifications
      # when double puppeting is enabled
      sync_with_custom_puppets: false
      # Whether or not to update the m.direct account data event when double puppeting is enabled.
      # Note that updating the m.direct event is not atomic (except with mautrix-asmux)
      # and is therefore prone to race conditions.
      sync_direct_chat_list: false
      # Allow using double puppeting from any server with a valid client .well-known file.
      double_puppet_allow_discovery: false
      # Servers to allow double puppeting from, even if double_puppet_allow_discovery is false.
      double_puppet_server_map:
        example.com: https://example.com
      # Shared secret for https://github.com/devture/matrix-synapse-shared-secret-auth
      #
      # If set, custom puppets will be enabled automatically for local users
      # instead of users having to find an access token and run `login-matrix`
      # manually.
      # If using this for other servers than the bridge's server,
      # you must also set the URL in the double_puppet_server_map.
      login_shared_secret_map:
        example.com: foo
      # Whether or not created rooms should have federation enabled.
      # If false, created portal rooms will never be federated.
      federate_rooms: true
      # End-to-bridge encryption support options. You must install the e2be optional dependency for
      # this to work. See https://docs.mau.fi/bridges/general/end-to-bridge-encryption.html
      encryption:
        # Allow encryption, work in group chat rooms with e2ee enabled
        allow: false
        # Default to encryption, force-enable encryption in all portals the bridge creates
        # This will cause the bridge bot to be in private chats for the encryption to work properly.
        default: false
        # Options for automatic key sharing.
        key_sharing:
          # Enable key sharing? If enabled, key requests for rooms where users are in will be fulfilled.
          # You must use a client that supports requesting keys from other users to use this feature.
          allow: false
          # Require the requesting device to have a valid cross-signing signature?
          # This doesn't require that the bridge has verified the device, only that the user has verified it.
          # Not yet implemented.
          require_cross_signing: false
          # Require devices to be verified by the bridge?
          # Verification by the bridge is not yet implemented.
          require_verification: true
      # Whether or not to explicitly set the avatar and room name for private
      # chat portal rooms. This will be implicitly enabled if encryption.default is true.
      private_chat_portal_meta: false
      # Whether or not the bridge should send a read receipt from the bridge bot when a message has
      # been sent to Signal. This let's you check manually whether the bridge is receiving your
      # messages.
      # Note that this is not related to Signal delivery receipts.
      delivery_receipts: false
      # Whether or not delivery errors should be reported as messages in the Matrix room. (not yet implemented)
      delivery_error_reports: false
      # Set this to true to tell the bridge to re-send m.bridge events to all rooms on the next run.
      # This field will automatically be changed back to false after it,
      # except if the config file is not writable.
      resend_bridge_info: false
      # Interval at which to resync contacts (in seconds).
      periodic_sync: 0

      # Provisioning API part of the web server for automated portal creation and fetching information.
      # Used by things like mautrix-manager (https://github.com/tulir/mautrix-manager).
      provisioning:
        # Whether or not the provisioning API should be enabled.
        enabled: true
        # The prefix to use in the provisioning API endpoints.
        prefix: /_matrix/provision
        # The shared secret to authorize users of the API.
        # Set to "generate" to generate and save a new token.
        shared_secret: generate
        # Segment API key to enable analytics tracking for web server
        # endpoints. Set to null to disable.
        # Currently the only events are login start, QR code scan, and login
        # success/failure.
        segment_key: null

      # The prefix for commands. Only required in non-management rooms.
      command_prefix: "!signal"

      # Messages sent upon joining a management room.
      # Markdown is supported. The defaults are listed below.
      management_room_text:
        # Sent when joining a room.
        welcome: "Hello, I'm a Signal bridge bot."
        # Sent when joining a management room and the user is already logged in.
        welcome_connected: "Use `help` for help."
        # Sent when joining a management room and the user is not logged in.
        welcome_unconnected: "Use `help` for help or `link` to log in."
        # Optional extra text sent when joining a management room.
        additional_help: ""

      # Send each message separately (for readability in some clients)
      management_room_multiple_messages: false

      # Permissions for using the bridge.
      # Permitted values:
      #      relay - Allowed to be relayed through the bridge, no access to commands.
      #       user - Use the bridge with puppeting.
      #      admin - Use and administrate the bridge.
      # Permitted keys:
      #        * - All Matrix users
      #   domain - All users on that homeserver
      #     mxid - Specific user
      permissions:
        "*": "relay"
        "{{ include "matrix.hostname" . }}": "user"
        "@admin:{{ include "matrix.hostname" . }}": "admin"

      relay:
        # Whether relay mode should be allowed. If allowed, `!signal set-relay` can be used to turn any
        # authenticated user into a relaybot for that chat.
        enabled: false
        # The formats to use when sending messages to Signal via a relay user.
        #
        # Available variables:
        #   $sender_displayname - The display name of the sender (e.g. Example User)
        #   $sender_username    - The username (Matrix ID localpart) of the sender (e.g. exampleuser)
        #   $sender_mxid        - The Matrix ID of the sender (e.g. @exampleuser:example.com)
        #   $message            - The message content
        message_formats:
          m.text: '$sender_displayname: $message'
          m.notice: '$sender_displayname: $message'
          m.emote: '* $sender_displayname $message'
          m.file: '$sender_displayname sent a file'
          m.image: '$sender_displayname sent an image'
          m.audio: '$sender_displayname sent an audio file'
          m.video: '$sender_displayname sent a video'
          m.location: '$sender_displayname sent a location'

    # Python logging configuration.
    #
    # See section 16.7.2 of the Python documentation for more info:
    # https://docs.python.org/3.6/library/logging.config.html#configuration-dictionary-schema
    logging:
      version: 1
      formatters:
        normal:
          format: "[%(asctime)s] [%(levelname)s@%(name)s] %(message)s"
      handlers:
        console:
          class: logging.StreamHandler
          formatter: normal
      loggers:
        mau:
          level: INFO
        aiohttp:
          level: WARN
      root:
          level: INFO
          handlers: 
            - console 
{{- end }}
{{- end -}}