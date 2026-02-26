control 'SV-278675' do
  title 'Microsoft Defender AV must report Dynamic Signature dropped events.'
  desc %q(Microsoft Defender Antivirus logs "Dynamic Signature dropped" events when it blocks or removes a file based on a dynamically updated signature, but the signature itself is dropped, meaning it was not fully processed or applied. This can indicate a potential issue with signature updates or the system's ability to handle them.)
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Reporting >> Configure whether to report Dynamic Signature dropped events is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting

Criteria: If the value "EnableDynamicSignatureDroppedEventReporting" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Reporting >> Configure whether to report Dynamic Signature dropped events to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83209r1144072_chk'
  tag severity: 'medium'
  tag gid: 'V-278675'
  tag rid: 'SV-278675r1144073_rule'
  tag stig_id: 'WNDF-AV-000071'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83114r1133716_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 1 => Passes
    # Value = 0 => FAILS
    its('EnableDynamicSignatureDroppedEventReporting') { should eq 1 }
  end

end
