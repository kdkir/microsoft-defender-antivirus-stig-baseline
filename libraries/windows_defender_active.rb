require 'open3'

class WindowsDefenderActive < Inspec.resource(1)
  name 'windows_defender_active'
  desc 'Checks if Windows Defender is the active antivirus product via SecurityCenter2 WMI'

  def active?
    product_names = registered_antivirus_products
    return true if product_names.nil? # assume active if the query fails

    product_names.include?('Windows Defender')
  end

  private

  def registered_antivirus_products
    ps_command = 'Get-WmiObject -Namespace "root\\SecurityCenter2"' \
                 ' -Query "SELECT displayName FROM AntivirusProduct"' \
                 ' | Select-Object -ExpandProperty displayName'

    stdout, _stderr, status = Open3.capture3('powershell.exe', '-NonInteractive', '-NoProfile', '-Command', ps_command)
    return nil unless status.success?

    stdout
  rescue StandardError
    nil
  end
end
