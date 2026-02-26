control 'SV-278655' do
  title 'Microsoft Defender AV must block abuse of exploited vulnerable signed drivers.'
  desc 'This policy setting prevents an application from writing a vulnerable signed driver to disk. Vulnerable signed drivers can be exploited by local applications that have sufficient privileges to gain access to the kernel. Vulnerable signed drivers enable attackers to disable or circumvent security solutions, eventually leading to system compromise.

The Block abuse of exploited vulnerable signed drivers rule does not block a driver already existing on the system from being loaded.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "56a863a9-875e-4185-98a7-b882c64b5ce5" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "56a863a9-875e-4185-98a7-b882c64b5ce5" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83189r1144048_chk'
  tag severity: 'medium'
  tag gid: 'V-278655'
  tag rid: 'SV-278655r1144049_rule'
  tag stig_id: 'WNDF-AV-000051'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83094r1134290_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
