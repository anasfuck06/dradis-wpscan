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
      data['wpscan_version']    = data.dig('banner', 'version')
      data['start_time']        = DateTime.strptime(data['start_time'].to_s,'%s')
      data['elapsed']           = "#{data["elapsed"]} seconds"
      data['wordpress_version'] = data.dig('version', 'number')   if data['version']
      data['plugins_string']    = data['plugins'].keys.join("\n") if data['plugins']
      data['themes_string']     = data['themes'].keys.join("\n")  if data['themes']
      data['users']             = data['users'].keys.join("\n")   if data['users']

      scan_info = template_service.process_template(template: 'scan_info', data: data)
      content_service.create_note text: scan_info

      # Parse vulnerability data and make more human readable.
      # NOTE: You need an API token for the WPVulnDB vulnerability data.
      vulnerabilities = []

      # WordPress Vulnerabilities
      if data['version'] && data['version']['status'] == 'insecure'
        data['version']['vulnerabilities'].each do |vulnerability_data|
          vulnerabilities << add_vulnerability( vulnerability_data )
        end
      end

      # Plugin Vulnerabilities
      if data['plugins']
        data['plugins'].each do |key, plugin|
          if plugin['vulnerabilities']
            plugin['vulnerabilities'].each do |vulnerability_data|
              vulnerabilities << add_vulnerability( vulnerability_data )
            end
          end
        end
      end

      # Theme Vulnerabilities
      if data['themes']
        data['themes'].each do |key, theme|
          if theme['vulnerabilities']
            theme['vulnerabilities'].each do |vulnerability_data|
              vulnerabilities << add_vulnerability( vulnerability_data )
            end
          end
        end
      end

      # Add vulnerabilities from WPVulnDB to Dradis
      vulnerabilities.each do |vulnerability|
        logger.info { "Adding vulnerability: #{vulnerability['title']}" }

        vulnerability_template = template_service.process_template(template: 'vulnerability', data: vulnerability)
        content_service.create_issue(text: vulnerability_template, id: vulnerability['wpvulndb_id'])
      end

      # Add bespoke/config vulnerabilities to Dradis
      #
      # TODO: Would be better to add the URL & passwords as evidence.
      # But not sure what to use as a "node" value?
      #
      # TODO: Can we add severity to issues?
      #
      # Note: No API key needed.
      vulnerabilities = []

      if data['config_backups']
        vulnerability = {}
        vulnerability['title'] = 'WordPress Configuration Backup Found'
        vulnerability['url']   = data['config_backups'].keys[0]

        vulnerabilities << vulnerability
      end

      if data['db_exports']
        vulnerability = {}
        vulnerability['title'] = 'Database Backup File Found'
        vulnerability['url']   = data['db_exports'].keys[0]

        vulnerabilities << vulnerability
      end

      if data['timthumbs']
        vulnerability = {}
        vulnerability['title'] = "Timthumb RCE File Found"
        vulnerability['url']   = data['timthumbs'].keys[0]

        vulnerabilities << vulnerability
      end

      if data['password_attack']
        data['password_attack'].each do |user|
          vulnerability = {}
          vulnerability['title'] = "WordPress #{user[0]}:#{user[1]['password']} User/Password Found"

          vulnerabilities << vulnerability
        end
      end

      # Add WordPress configuration vulnerabilities to Dradis
      vulnerabilities.each do |vulnerability|
        logger.info { "Adding vulnerability: #{vulnerability['title']}" }

        vulnerability_template = template_service.process_template(template: 'vulnerability', data: vulnerability)
        issue = content_service.create_issue(text: vulnerability_template, id: "wpscan_#{rand(999999)}")
      end

    end

    def add_vulnerability( vulnerability_data )
      wpvulndb_url = 'https://wpvulndb.com/vulnerabilities/'

      vulnerability = {}
      vulnerability['title']        = vulnerability_data['title']
      vulnerability['fixed_in']     = vulnerability_data['fixed_in'] if vulnerability_data['fixed_in']
      vulnerability['cve']          = 'CVE-' + vulnerability_data['references']['cve'][0] if vulnerability_data['references']['cve']
      vulnerability['url']          = vulnerability_data['references']['url'].join("\n") if vulnerability_data['references']['url']
      vulnerability['wpvulndb_url'] = wpvulndb_url + vulnerability_data['references']['wpvulndb'][0]
      vulnerability['wpvulndb_id']  = vulnerability_data['references']['wpvulndb'][0]

      vulnerability
    end
  end
end
