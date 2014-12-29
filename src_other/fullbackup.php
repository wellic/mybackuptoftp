#!/usr/local/psa/bin/sw-engine-pleskrun
<?php

function usage() {
        print <<<USAGE
Usage:

Backup - output is fullbackup_<datestamp>
-b								Back up to local repository
-b -o <output_dir>						Back up to directory
-b -o ftp://<login>:<password>@<server>/<output_dir>		Back up to FTP
-p <backup_password>						Set backup password, supported since Plesk 11

--per-domain							Back up per domain, default - all server at once

Restore - input is fullbackup_<datestamp>
-r fullbackup_<datestamp>					Restore fullbackup_<datestamp>
-r ftp://<login>:<password>@<server>/fullbackup_<datestamp>	Restore fullbackup_<datestamp> from FTP
-p <backup_password>

Export
-e <backup_info_xml> <output_file>				Export backup from local repository to file

USAGE;
}

if ($argc < 2)
	return usage();

$isWindows = stristr(PHP_OS, 'win') ? true : false;
if ($isWindows) {
	$plesk_dir = chop(getenv('plesk_dir'), '/\\');
	$cmd_prefix = '--';
	$backup_repo = chop(get_config_string('DUMP_D'), '/\\');
} else {
	$plesk_dir = '/usr/local/psa';
	$cmd_prefix = '';

	$backup_repo = '/var/lib/psa/dumps';
	$conf = fopen('/etc/psa/psa.conf', 'r');
	if (!$conf)
		die("fopen(/etc/psa/psa.conf) failed\n");
	while ($s = fgets($conf))
		if (preg_match('/\s*DUMP_D\s+(\S+)/', $s, $m)) {
			$backup_repo = chop($m[1], '/\\');
			break;
		}
	fclose($conf);
}

$version = "$plesk_dir/version";
if (!file_exists($version))
	die("The file \"$version\" has not been found.\n");

$version_s = chop(file_get_contents($version));
if (!preg_match('/^(\d?\d)\./', $version_s, $v))
	die("Failed to get Plesk version from \"$version\"\n");

list($version, $major) = $v;

$pleskbackup = "$plesk_dir/bin/pleskbackup";
$pleskrestore = "$plesk_dir/bin/pleskrestore";
if (!$isWindows)
	if (!file_exists($pleskbackup) || !file_exists($pleskrestore))
		die("'pleskbackup' or 'pleskrestore' util isn't exist: package 'psa-backup-manager' must be installed\n");
$pmmcli = "$plesk_dir/admin/bin/pmmcli";

$output_dir = NULL;
$fullbackup_h = NULL;
$backup_password = NULL;
$per_domain = false;

if ($argv[1] == '-b') {
	if ($argc > 7)
		return usage();

	$ftp = false;

	for ($i = 2; $i < $argc; ++$i) {
		$arg = $argv[$i];
		if ($arg == '-o') {
			$output_dir = $argv[++$i];
			if (!$output_dir)
				return usage();
			$output_dir = chop($output_dir, '/\\');

			$ftp = strncmp($output_dir, 'ftp://', 6) == 0;
			if (!$ftp) {
				if (!is_abs_path($output_dir))
					$output_dir = chop(getcwd(), '/\\') . "/$output_dir";

				if (!file_exists($output_dir)) {
					if (!mkdir($output_dir, 0777, true))
						die("mkdir($output_dir) failed\n");
				}
			} else {
				$m = array();
				if (!preg_match('#ftp://(.+?):(.*?)@([^/]+)/?(.+)?#', $output_dir, $m))
					die("Failed to parse FTP output location '$output_dir'\n");
				list($output_dir, $ftp_user, $ftp_passwd, $ftp_host) = $m;
				$ftp_dir = (count($m) == 5 ? $m[4] : '');

				$fr = ftp_connect($ftp_host);
				if (!$fr)
					die("ftp_connect($ftp_host) failed\n");

				if (!ftp_login($fr, $ftp_user, $ftp_passwd))
					die("ftp_login($ftp_user) failed\n");

				if ($ftp_dir)
					@ftp_mkdir($fr, $ftp_dir);

				ftp_close($fr);
			}
		} else if ($arg == '-p') {
			if ($major < 11)
				die("Backup password option is supported only since Plesk 11\n");

			$backup_password = $argv[++$i];
		} else if ($arg == '--per-domain')
			$per_domain = true;
		else
			return usage();
	}

	if (function_exists('date_default_timezone_set'))
		date_default_timezone_set(@date_default_timezone_get());

	$fb_path = 'fullbackup_' . date('ymdhis');
	if ($output_dir)
		$fb_path = "$output_dir/$fb_path";
	else
		$fb_path = chop(getcwd(), '/\\') . "/$fb_path";

	$fullbackup_h = fopen($fb_path, 'w');
	if (!$fullbackup_h)
		die("fopen($fb_path) failed\n");

	if (!$per_domain)
		backup_server(false);
	else {
		backup_server(true);

		db_connect();
		$res = mysql_query("select id from clients where login = 'admin'");
		if (!$res)
			die('mysql_query(admin) failed: ' . mysql_error() . "\n");
		db_close();

		if ($r = mysql_fetch_row($res))
			backup_client($r[0]);
	}

	fclose($fullbackup_h);

	if (!$ftp)
		print "Created full server backup '$fb_path'\n";
	else
		print "Created full server backup '" . preg_replace('#(ftp://.+?):.*?@#', '\1@', $fb_path) . "'\n";
} else if ($argv[1] == '-r') {
	if ($argc != 3 && $argc != 5)
		return usage();

	$fb_path = $argv[2];
	$ftp = strncmp($fb_path, 'ftp://', 6) == 0;

	if ($argc == 5) {
		if ($argv[3] == '-p') {
			if ($major < 11)
				die("Backup password option is supported only since Plesk 11\n");

			$backup_password = $argv[4];
		} else
			return usage();
	}

	$fullbackup_h = fopen($fb_path, 'r');
	if (!$fullbackup_h)
		die("fopen($fb_path) failed\n");

	while($l = fgets($fullbackup_h)) {
		if (!$ftp)
			restore(chop($l));
		else
			restore_ftp(chop($l));
	}

	fclose($fullbackup_h);
} else if ($argv[1] == '-e') {
	if ($argc != 4)
		return usage();

	$backup_info = $argv[2];
	$output_file = $argv[3];

	$backup_repo_r = realpath($backup_repo);
	if (!$backup_repo_r)
		die("Failed to get realpath for local repository '$backup_repo'\n");

	$backup_info_r = realpath($backup_info);
	if (!$backup_info_r) {
		$backup_info_r = realpath("$backup_repo_r/$backup_info");
		if (!$backup_info_r)
			die("Failed to get realpath for backup info '$backup_info'\n");
	}

	$pos = stripos($backup_info_r, $backup_repo_r);
	if ($pos !== 0)
		die("Backup info '$backup_info_r' doesn't belong to local repository '$backup_repo_r'\n");

	$backup_info_b = ltrim(str_ireplace($backup_repo_r, '', $backup_info_r), '/\\');

	$output_dir = dirname($output_file);
	if (!is_abs_path($output_dir))
		$output_dir = chop(getcwd(), '/\\') . "/$output_dir";

	if (!file_exists($output_dir)) {
		if (!mkdir($output_dir, 0777, true))
			die("mkdir($output_dir) failed\n");
	}

	export_backup($backup_info_b, $output_dir, basename($output_file));
} else
	return usage();

$port = NULL;
$passwd = NULL;
$my = NULL;

function db_connect() {
	global $isWindows, $port, $passwd, $my;
	if (!$port) {
		if ($isWindows) {
			$port = 8306;
			$passwd = get_admin_password();
		} else {
			$port = 3306;
			$passwd = file_get_contents('/etc/psa/.psa.shadow');
			$passwd = chop($passwd);
		}
	}

	$my = mysql_connect("localhost:$port", 'admin', $passwd);
	if (!$my)
		die("mysql_connect() failed\n");

	if (!mysql_query('use psa'))
		die('mysql_query(psa) failed: ' . mysql_error() . "\n");
}

function db_close() {
	global $my;
	mysql_close($my);
	$my = NULL;
}

function is_abs_path($path) {
	if (!$path)
		return false;

	if ($path[0] == '/')
		return true;

	global $isWindows;
	if ($isWindows) {
		if ($path[0] == '\\')
			return true;

		if (strlen($path) > 1 && $path[1] == ':')
			return true;
	}

	return false;
}

function expand_file($f) {
	global $isWindows;
	if (!$isWindows)
		return `echo -n $f`;
	else {
		$f = str_replace('/', '\\', $f);
		return dirname($f) . '\\' . chop(`dir /b "$f"`);
	}
}

function exec_util($cmd) {
	system($cmd);
}

function backup_server($only_configuration) {
	global $pleskbackup, $cmd_prefix, $output_dir, $fullbackup_h, $backup_password;

	print "Back up server\n";

	$cmd = "\"$pleskbackup\" ${cmd_prefix}server";
	if ($only_configuration) $cmd .= ' -c';
	$f = 'server_' . date('ymdhis');
	$cmd .= " --prefix=\"$f\"";
	if ($output_dir) {
		$of = "$output_dir/$f";
		$cmd .= " --output-file=\"$of\"";
	}
	if ($backup_password)
		$cmd .= ' ' . escapeshellarg("--backup-password=$backup_password");

	exec_util($cmd);
	if (!$output_dir) {
		global $backup_repo;
		$bf = "$backup_repo/$f*.xml";
		$of = expand_file($bf);
		if (!file_exists($of))
			print "Couldn't find server backup '$bf' in local repository\n";
	}

	fwrite($fullbackup_h, "$of\n");
}

function backup_client($client_id, $level = '') {
	global $pleskbackup, $cmd_prefix, $output_dir, $fullbackup_h, $backup_password;

	db_connect();
	$res = mysql_query("select id, type, login from clients where id = $client_id");
	if (!$res)
		die('mysql_query(client) failed: ' . mysql_error() . "\n");
	db_close();

	list($id, $type, $login) = mysql_fetch_row($res);
	if ($type != 'admin') {
		$level .= "/${type}s/${login}";

		print "Back up $type #$client_id - $login\n";

		$cmd  = "\"$pleskbackup\" ${cmd_prefix}${type}s-id $client_id -c";

		$f = "${type}_${login}_" . date('ymdhis');
		$cmd .= " --prefix=\"$f\"";
		if ($output_dir) {
			$of = "$output_dir/$f";
			$cmd .= " --output-file=\"$of\"";
		}
		if ($backup_password)
			$cmd .= ' ' . escapeshellarg("--backup-password=$backup_password");

		exec_util($cmd);
		if (!$output_dir) {
			global $backup_repo;
			$bf = "$backup_repo$level/$f*.xml";
			$of = expand_file($bf);
			if (!file_exists($of))
				print "Couldn't find $type backup '$bf' in local repository\n";
		}

		fwrite($fullbackup_h, "$of\n");
	}

	db_connect();
	$res = mysql_query("select id, name from domains where cl_id = $client_id and webspace_id = 0");
	if (!$res)
		die('mysql_query(domains) failed: ' . mysql_error() . "\n");
	db_close();

	while ($r = mysql_fetch_row($res)) {
		list($id, $name) = $r;
		backup_domain($id, $name, $level);
	}

	db_connect();
	$res = mysql_query("select id from clients where parent_id = $client_id");
	if (!$res)
		die('mysql_query(clients) failed: ' . mysql_error() . "\n");
	db_close();

	while ($r = mysql_fetch_row($res)) {
		list($id) = $r;
		backup_client($id, $level);
	}
}

function backup_domain($id, $name, $level) {
	global $pleskbackup, $cmd_prefix, $output_dir, $fullbackup_h, $backup_password;

	print "Back up domain #$id - $name\n";

	$cmd  = "\"$pleskbackup\" ${cmd_prefix}domains-id $id";

	$f = "domain_${name}_" . date('ymdhis');
	$cmd .= " --prefix=\"$f\"";
	if ($output_dir) {
		$of = "$output_dir/$f";
		$cmd .= " --output-file=\"$of\"";
	}
	if ($backup_password)
		$cmd .= ' ' . escapeshellarg("--backup-password=$backup_password");

	exec_util($cmd);
	if (!$output_dir) {
		global $backup_repo;
		$bf = "$backup_repo$level/domains/$name/$f*.xml";
		$of = expand_file($bf);
		if (!file_exists($of))
			print "Couldn't find domain backup '$bf' in local repository\n";
	}

	fwrite($fullbackup_h, "$of\n");
}

function restore($backup) {
	global $pleskrestore, $backup_password;

	print "Restore '$backup'\n";

	$bn = basename($backup);
	$level = substr($bn, 0, strpos($bn, '_'));
	if ($level != 'server')
		$level .= 's';

	$cmd = "\"$pleskrestore\" --restore \"$backup\" -level $level";
	if ($backup_password)
		$cmd .= ' -backup-password ' . escapeshellarg($backup_password);
	exec_util($cmd);
}

function my_shell_exec($cmd, $stdin) {
	$pipes = array();
	$proc = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);
	if (!$proc)
		die("proc_open($cmd) failed\n");

	if (!fwrite($pipes[0], $stdin))
		die("fwrite() failed\n");
	fclose($pipes[0]);

	$stdout = stream_get_contents($pipes[1]);
	fclose($pipes[1]);

	proc_close($proc);
	return $stdout;
}

function get_xpath($response) {
	$doc = new DOMDocument();
	$doc->loadXML($response);
	$xpath = new DOMXPath($doc);

	$errcode = $xpath->query('/response/errcode')->item(0)->nodeValue;	
	if ($errcode != 0) {
		$errmsg = $xpath->query('/response/errmsg')->item(0)->nodeValue;
		die("$errmsg\n");
	}

	return $xpath;
}

function restore_ftp($backup) {
	global $pmmcli, $backup_password;

	print "Restore '$backup'\n";

	db_connect();
	$res = mysql_query("select guid from clients where login = 'admin'");
	if (!$res)
		die('mysql_query(admin) failed: ' . mysql_error() . "\n");
	db_close();

	list($admin_guid) = mysql_fetch_row($res);

	$m = array();
	if (!preg_match('#ftp://(.*?):(.*?)@(.*?)/(.*/)?([^/]+)#', $backup, $m))
		die("Failed to parse FTP backup file location '$backup'\n");
	list($backup, $ftp_user, $ftp_passwd, $ftp_host, $ftp_dir, $ftp_file) = $m;

	print "Running initial restore task\n";

	$rtask = <<<RTASK
<restore-task-description owner-guid="$admin_guid" owner-type="server">
	<source>
		<dump-specification>
			<dumps-storage-credentials storage-type="foreign-ftp">
				<login>$ftp_user</login>
				<password>$ftp_passwd</password>
				<hostname>$ftp_host</hostname>
				<root-dir>$ftp_dir</root-dir>
				<file-name>$ftp_file</file-name>
RTASK;
	if ($backup_password)
		$rtask .= <<<RTASK
				<backup-password>$backup_password</backup-password>
RTASK;
	$rtask .= <<<RTASK
			</dumps-storage-credentials>
		</dump-specification>
	</source>
	<objects>
		<all/>
	</objects>
	<misc verbose-level="5"/>
</restore-task-description>
RTASK;

	$response = my_shell_exec("\"$pmmcli\" --restore", $rtask);
	$xpath = get_xpath($response);
	if (!$xpath->query('/response/data/restore-task-result/conflicts-description')->item(0))
		$task_id =$xpath->query('/response/data/task-id')->item(0)->nodeValue;
	else {
		$session_id = $xpath->query('/response/data/restore-task-result/dump-overview')->item(0)->attributes->getNamedItem('session-id')->nodeValue;

		print "Running resolve conflicts task from session $session_id\n";

		$resolve_conflicts = <<<RESOLVE_CONFLICTS
<resolve-conflicts-task-description session-id="$session_id">
	<conflict-resolution-rules>
		<policy>
			<timing>
				<resolution><overwrite/></resolution>
			</timing>
			<resource-usage>
				<resolution><overuse/></resolution>
			</resource-usage>
			<configuration>
				<resolution><automatic/></resolution>
			</configuration>
		</policy>
	</conflict-resolution-rules>
</resolve-conflicts-task-description>
RESOLVE_CONFLICTS;

		$response = my_shell_exec("\"$pmmcli\" --resolve-conflicts", $resolve_conflicts);
		$xpath = get_xpath($response);

		$session_id = $xpath->query('/response/data/dump-overview')->item(0)->attributes->getNamedItem('session-id')->nodeValue;

		print "Running final restore task from session $session_id\n";

		$rtask = <<<RTASK
<restore-task-description owner-guid="$admin_guid" owner-type="server">
	<source>
		<session-id>$session_id</session-id>
	</source>
	<objects>
		<all/>
	</objects>
	<misc verbose-level="5"/>
</restore-task-description>
RTASK;

		$response = my_shell_exec("\"$pmmcli\" --restore", $rtask);
		$xpath = get_xpath($response);
		$task_id =$xpath->query('/response/data/task-id')->item(0)->nodeValue;
	}

	$response = `"$pmmcli" --get-task $task_id`;
	$xpath = get_xpath($response);

	$deployer_pid = NULL;
	$deploy = $xpath->query("/response/data/task-list/task[@task-id=$task_id]/task-status[@task-id=$task_id]/mixed/restore/deploy");
	if ($deploy->length != 0)
		$deployer_pid = $deploy->item(0)->attributes->getNamedItem('task-id')->nodeValue;
	if (!$deployer_pid)
		die("Failed to get deployer PID\n");

	print "Waiting for deployer process #$deployer_pid\n";

	global $isWindows;
	if (!$isWindows) {
		while (posix_kill($deployer_pid, 0))
			sleep(10);
	} else {
		while (stristr(`tasklist /FI "PID eq $deployer_pid" /FO CSV /NH`, 'deployer'))
			sleep(10);
	}

	$response = `"$pmmcli" --get-task $task_id`;
	$xpath = get_xpath($response);

	print "Restore task #$task_id finished:\n$response";
}

function export_backup($backup_info, $output_dir, $output_file) {
	global $backup_repo, $pmmcli;

	print "Export '$backup_info'\n";

$src_dst = <<<SRC_DST
<src-dst-files-specification>
	<src>
		<dumps-storage-credentials storage-type="local">
			<root-dir>$backup_repo</root-dir>
		</dumps-storage-credentials>
		<name-of-info-xml-file>$backup_info</name-of-info-xml-file>
	</src>
	<dst>
		<dumps-storage-credentials storage-type="file">
			<root-dir>$output_dir</root-dir>
			<file-name>$output_file</file-name>
		</dumps-storage-credentials>
	</dst>
</src-dst-files-specification>
SRC_DST;

	$response = my_shell_exec("\"$pmmcli\" --export-dump-as-file", $src_dst);
	$xpath = get_xpath($response);
}
