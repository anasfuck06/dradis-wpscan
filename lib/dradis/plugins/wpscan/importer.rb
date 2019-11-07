module Dradis::Plugins::Wpscan
  class Importer < Dradis::Plugins::Upload::Importer
    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params={})

      file_content = File.read( params[:file] )

      # Parse the uploaded file into a Ruby Hash
      logger.info { "Parsing WPScan output from #{ params[:file] }..." }
      data = MultiJson.decode(file_content)
      logger.info { 'Done.' }

      # Do a sanity check to confirm the user uploaded the right file
      # format.
      logger.info {  data["banner"]["description"] }
      logger.info { data["banner"]["description"].nil? }
      unless data["banner"]["description"] == "WordPress Security Scanner by the WPScan Team"
        logger.error "ERROR: no 'banner->description' field present in the provided "\
                     "JSON data. Are you sure you uploaded a WPScan JSON output file?"
        exit(-1)
      end

      # Parse the `data` structure and call template_service and
      # content_service to create data in the project.
    end
  end
end
