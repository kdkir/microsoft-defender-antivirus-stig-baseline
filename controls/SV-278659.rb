control 'SV-278659' do
  title 'Microsoft Defender AV must randomize scheduled task times.'
  desc 'In Microsoft Defender Antivirus, randomize the start time of the scan to any interval from 0 to 23 hours. By default, scheduled tasks begin at a random time within four hours of the time specified in Task Scheduler.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Randomize scheduled task times is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "RandomizeScheduleTaskTimes" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Randomize scheduled task times to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83193r1144054_chk'
  tag severity: 'medium'
  tag gid: 'V-278659'
  tag rid: 'SV-278659r1144055_rule'
  tag stig_id: 'WNDF-AV-000055'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83098r1133668_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
