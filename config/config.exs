import Config

config :ash, :validate_domain_config_inclusion?, false

# Required by Ash >= 3.37. Codepoints match how SQL data layers count
# string length (same choice as roadmapp3r).
config :ash, default_string_length_count: :codepoints

import_config "#{config_env()}.exs"
