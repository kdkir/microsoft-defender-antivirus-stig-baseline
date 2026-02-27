control 'SV-213434' do
  title 'Microsoft Defender AV must join Microsoft MAPS.'
  desc 'This policy setting allows joining Microsoft MAPS. Microsoft MAPS is the online community that helps in choosing how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new definitions and protect your computer. This information can include things like location of detected items on your computer if harmful software was removed. The information will be automatically collected and sent. In some instances personal information might unintentionally be sent to Microsoft. However Microsoft will not use this information to identify you or contact you. 

Possible options are: 
(0x0) Disabled (default) 
(0x1) Basic membership 
(0x2) Advanced membership 

Basic membership will send basic information to Microsoft about software that has been detected, including where the software came from, the actions that you apply or that are applied automatically, and whether the actions were successful. Advanced membership will send, in addition to basic information, more information to Microsoft about malicious software spyware and potentially unwanted software, including the location of the software file names, how the software operates, and how it has impacted your computer. 

If this setting is enabled, you will join Microsoft MAPS with the membership specified. If this setting is disabled or do not configured, you will not join Microsoft MAPS. In Windows 10, Basic membership is no longer available, so setting the value to 1 or 2 enrolls the device into Advanced membership.'
  desc 'check', 'This is applicable to unclassified systems. For other systems, this is Not Applicable.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MAPS >> "Join Microsoft MAPS" is set to "Enabled" and "Advanced MAPS" is selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet

Criteria: If the value "SpynetReporting" is REG_DWORD = 1, or REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'This is applicable to unclassified systems. For other systems this is Not Applicable.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MAPS >> "Join Microsoft MAPS" to "Enabled" and select "Basic MAPS" or "Advanced MAPS" from the drop-down box.'
  impact 0.5
  tag check_id: 'C-14659r1133628_chk'
  tag severity: 'medium'
  tag gid: 'V-213434'
  tag rid: 'SV-213434r1134051_rule'
  tag stig_id: 'WNDF-AV-000010'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14657r1133629_fix'
  tag 'documentable'
  tag legacy: ['SV-89847', 'V-75167']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet'

  describe registry_key(registry_path) do
    # Default behavior is 1, https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowcloudprotection
    its('SpynetReporting') { should be_nil.or be_in [1, 2] }
  end

end
