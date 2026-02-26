control 'SV-278648' do
  title 'Microsoft Defender AV must block credential stealing from the Windows local security authority subsystem.'
  desc 'This policy setting helps prevent credential stealing by locking down Local Security Authority Subsystem Service (LSASS).'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83182r1144031_chk'
  tag severity: 'medium'
  tag gid: 'V-278648'
  tag rid: 'SV-278648r1144032_rule'
  tag stig_id: 'WNDF-AV-000044'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83087r1134294_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }
    its('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2') { should eq "1" }
  end

end
