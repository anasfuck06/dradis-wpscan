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
      if data['target_url'].nil?
        logger.error "ERROR: no 'banner->description' field present in the provided "\
                     "JSON data. Are you sure you uploaded a WPScan JSON output file?"
        exit(-1)
      end

      # Parse scan info data and make more human readable.
      data["wpscan_version"] = data["banner"]["version"]
      data["start_time"]     = DateTime.strptime(data["start_time"].to_s,'%s')
      data["elapsed"]        = "#{data["elapsed"]} seconds"

      scan_info = template_service.process_template(template: 'scan_info', data: data)
      content_service.create_note text: scan_info

      # Parse vulnerability data and make more human readable.
      # NOTE: You need an API token for the vulnerability data.
      vulnerabilities = []

      # WordPress Vulnerabilities
      if data["version"] && data["version"]["status"] == "insecure"
        data["version"]["vulnerabilities"].each do |vulnerability_data|
          add_vulnerability( vulnerabilities, vulnerability_data )
        end
      end

      # Plugin Vulnerabilities
      if data["plugins"]
        data["plugins"].each do |key, plugin|
          if plugin['vulnerabilities']
            plugin['vulnerabilities'].each do |vulnerability_data|
              add_vulnerability( vulnerabilities, vulnerability_data )
            end
          end
        end
      end

      # Theme Vulnerabilities
      if data["themes"]
        data["themes"].each do |key, theme|
          if theme['vulnerabilities']
            theme['vulnerabilities'].each do |vulnerability_data|
              add_vulnerability( vulnerabilities, vulnerability_data )
            end
          end
        end
      end

      # if data["config_backups"]
      #   vulnerability = {}
      #   vulnerability["title"] = "WordPress Configuration Backup Found"
      #   vulnerability["url"]   = data["config_backups"][0]

      #   vulnerabilities << vulnerability
      # end

      vulnerabilities.each do |vulnerability|
        vulnerability = template_service.process_template(template: 'vulnerability', data: vulnerability)
        content_service.create_note text: vulnerability
      end
    end

    def add_vulnerability( vulnerabilities, vulnerability_data )
      wpvulndb_url = "https://wpvulndb.com/vulnerabilities/"

      vulnerability = {}
      vulnerability["title"]    = vulnerability_data["title"]
      vulnerability["fixed_in"] = vulnerability_data["fixed_in"] if vulnerability_data["fixed_in"]
      vulnerability["cve"]      = "CVE-" + vulnerability_data["references"]["cve"][0] if vulnerability_data["references"]["cve"]
      vulnerability["url"]      = vulnerability_data["references"]["url"].join("\n") if vulnerability_data["references"]["url"]
      vulnerability["wpvulndb"] = wpvulndb_url + vulnerability_data["references"]["wpvulndb"][0]

      vulnerabilities << vulnerability
    end
  end
end
