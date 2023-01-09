
#!/bin/sh
HOSTNAME=`hostname`

LANG=C
export LANG

clear
sleep 1

SVersion=0.7.1
SLast_update=2019.08.01

function perm {
#!/bin/bash

ls -lLa $1 | while read DATA
do
  case "${DATA:0:1}" in
  "-"|"d")
    PERM=$( echo "${DATA:1:9}" | sed 's/-/0/g;s/r/4/g;s/w/2/g;s/x/1/g' )
    P_US=$((${PERM:0:1}+${PERM:1:1}+${PERM:2:1}))
    P_GR=$((${PERM:3:1}+${PERM:4:1}+${PERM:5:1}))
    P_OT=$((${PERM:6:1}+${PERM:7:1}+${PERM:8:1}))
    DATA=$( echo "$DATA" | sed "s/${DATA:0:10}/${P_US}${P_GR}${P_OT}/" )
    echo "$DATA"
  ;;
  *)
    continue
  ;;
  esac
done

exit 0
#finis

}

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#################################  Preprocessing...  #####################################"
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

# FTP 서비스 동작확인
find /etc/ -name "proftpd.conf" | grep "/etc/"                                                     > proftpd.txt
find /etc/ -name "vsftpd.conf" | grep "/etc/"                                                      > vsftpd.txt
profile=`cat proftpd.txt`
vsfile=`cat vsftpd.txt`


############################### APACHE Check Process Start ##################################

#0. 필요한 함수 선언

apache_awk() {
	if [ `ps -ef | grep -i $1 | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
	then
		apaflag=8
	elif [ `ps -ef | grep -i $1 | grep -v "ns-httpd" | grep -v "grep" | awk '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
	then
		apaflag=9
	fi
}


# 1. 아파치 프로세스 구동 여부 확인 및 아파치 TYPE 판단, awk 컬럼 확인

if [ `ps -ef | grep -i "httpd" | grep -v "ns-httpd" | grep -v "lighttpd" | grep -v "grep" | wc -l` -gt 0 ]
then
	apache_type="httpd"
	apache_awk $apache_type

elif [ `ps -ef | grep -i "apache2" | grep -v "ns-httpd" | grep -v "lighttpd" | grep -v "grep" | wc -l` -gt 0 ]
then
	apache_type="apache2"
	apache_awk $apache_type
else
	apache_type="null"
	apaflag=0	
fi

# 2. 아파치 홈 디렉토리 경로 확인

if [ $apaflag -ne 0 ]
then

	if [ `ps -ef | grep -i $apache_type | grep -v "ns-httpd" | grep -v "grep" | awk -v apaflag2=$apaflag '{print $apaflag2}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
	then
		APROC1=`ps -ef | grep -i $apache_type | grep -v "ns-httpd" | grep -v "grep" | awk -v apaflag2=$apaflag '{print $apaflag2}' | grep "/" | grep -v "httpd.conf" | uniq`
		APROC=`echo $APROC1 | awk '{print $1}'`
		$APROC -V > APROC.txt 2>&1
				
		ACCTL=`echo $APROC | sed "s/$apache_type$/apachectl/"`
		$ACCTL -V > ACCTL.txt 2>&1
				
		if [ `cat APROC.txt | grep -i "root" | wc -l` -gt 0 ]
		then
			AHOME=`cat APROC.txt | grep -i "root" | awk -F"\"" '{print $2}'`
			ACFILE=`cat APROC.txt | grep -i "server_config_file" | awk -F"\"" '{print $2}'`
		else
			AHOME=`cat ACCTL.txt | grep -i "root" | awk -F"\"" '{print $2}'`
			ACFILE=`cat ACCTL.txt | grep -i "server_config_file" | awk -F"\"" '{print $2}'`
		fi
	fi
	
	if [ -f $AHOME/$ACFILE ]
	then
		ACONF=$AHOME/$ACFILE
	else
		ACONF=$ACFILE
	fi	
fi

# 3. 불필요한 파일 삭제

rm -rf APROC.txt
rm -rf ACCTL.txt

################################ APACHE Check Process End ###################################






echo " " > $HOSTNAME.sol.result.txt 2>&1

echo "***************************************************************************************"
echo "***************************************************************************************"
echo "*                                                                                     *"
echo "*  Solaris Security Checklist version $SVersion                                       *"
echo "*                                                                                     *"
echo "***************************************************************************************"
echo "***************************************************************************************"

echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo "■■■■■■■■■■■■■■■■■■■             Solaris Security Check           	 ■■■■■■■■■■■■■■■■■■■■" >> $HOSTNAME.sol.result.txt 2>&1
echo "■■■■■■■■■■■■■■■■■■■      Copyright ⓒ 2019, tndsoft    ■■■■■■■■■■■■■■■■■■■■" >> $HOSTNAME.sol.result.txt 2>&1
echo "■■■■■■■■■■■■■■■■■■■     Ver $SVersion // Last update $SLast_update ■■■■■■■■■■■■■■■■■■■■" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "################################### Start Time  #######################################"
date
echo "################################### Start Time  #######################################" >> $HOSTNAME.sol.result.txt 2>&1
date                                                                                           >> $HOSTNAME.sol.result.txt 2>&1

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "############################       1. 계정 관리        ################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0101 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################            root 계정 원격 접속 제한             ###################"
echo "###################           1.01 root 계정 원격 접속 제한             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/default/login 파일의 CONSOLE=/dev/console 라인에 주석(#)이 없으면 양호"     >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Enabled"
	else
		echo "☞ Telnet Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
	fi
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "③ /etc/default/login 파일 설정"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/login ]
then
  cat /etc/default/login | grep -i 'console.*' | grep '='                                      >> $HOSTNAME.sol.result.txt 2>&1
  flag2=`cat /etc/default/login | grep -i 'console.*' | grep '=' | grep -v "^#" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
else
  echo "/etc/default/login 파일이 없습니다."                                                   >> $HOSTNAME.sol.result.txt 2>&1
  flag2="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[SSH] /etc/ssh/sshd_config 파일 확인 "                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "--------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/ssh/sshd_config | egrep -i 'PermitRootLogin' 										>> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1




	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0101 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0102 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              패스워드 복잡성 설정               ###################"
echo "###################             1.02 패스워드 복잡성 설정               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패스워드 복잡도 설정이 되어있으면 양호"                                        >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "◈/etc/default/passwd 파일(solaris 10)"											>> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/passwd ]
then
  cat /etc/default/passwd | egrep "MINNONALPHA|MINALPHA|passlength|MINUPPER|MINLOWER|MINSPCIAL|MINDIGIT"   >> $HOSTNAME.sol.result.txt 2>&1
else
  echo "/etc/default/passwd 파일이 없습니다."                                                          >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0102 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0103 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             계정 잠금 임계값 설정               ###################"
echo "###################            1.03 계정 잠금 임계값 설정               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 계정 잠금 임계 값이 적절하게 설정되어 있는 경우 양호 (권고: 5회 이하)"           >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1)Solaris  9버전 이하: (RETRIES 5이하 이면 양호)"                             >> $HOSTNAME.sol.result.txt 2>&1 
echo "■       : (2)Solaris 10버전 이상: (RETRIES 5이하, LOCK_AFTER_RETRIES=YES 이면 양호)"     >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① Solaris 버전 확인"                                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
uname -a                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
flag3=`uname -a | awk -F" " '{print $3}'`
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② RETRIES 설정 확인(/etc/default/login 파일)"                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
grep RETRIES /etc/default/login | grep "="                                                     >> $HOSTNAME.sol.result.txt 2>&1
if	[	`grep RETRIES /etc/default/login | grep "=" | grep -v "^#" | wc -l` -gt 0 ]
then
	if [ `grep RETRIES /etc/default/login | grep "=" | grep -v "^#" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`=null ]
	then
		flag1="Null"
	else
		flag1=`grep RETRIES /etc/default/login | grep "=" | grep -v "^#" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`
	fi
else
	flag1="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "③ LOCK_AFTER_RETRIES 설정 확인(/etc/security/policy.conf 파일)"                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
grep LOCK_AFTER_RETRIES /etc/security/policy.conf | grep "="                                   >> $HOSTNAME.sol.result.txt 2>&1
if [ `grep LOCK_AFTER_RETRIES /etc/security/policy.conf | grep "=" | grep -v "^#" | wc -l` -gt 0 ]
then
	if [ `grep LOCK_AFTER_RETRIES /etc/security/policy.conf | grep "=" | grep -v "^#" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`=null ]
	then
		flag2="Null"
	else
		flag2=`grep LOCK_AFTER_RETRIES /etc/security/policy.conf | grep "=" | grep -v "^#" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`
	fi
else
	flag2="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[항목요약]"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "=============================================================================="          >> $HOSTNAME.sol.result.txt 2>&1
echo "# 계정 잠금정책 설정은 Solaris 10 버전에 새롭게 추가된 기능으로,"                        >> $HOSTNAME.sol.result.txt 2>&1
echo "# Solaris 10 이전 버전에는 해당 설정 항목이 존재하지 않습니다."                          >> $HOSTNAME.sol.result.txt 2>&1
echo "# 따라서, Solaris 10 이전 버전은 RETRIES=5 설정을 통하여 지정된 회수만큼"                >> $HOSTNAME.sol.result.txt 2>&1
echo "# 로그인 실패시 로그인 세션이 자동으로 닫히도록 설정하면 양호한 것으로 판단함."          >> $HOSTNAME.sol.result.txt 2>&1
echo "=============================================================================="          >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag3":"$flag1":"$flag2                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0103 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0104 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              패스워드 파일 보호                 ###################"
echo "###################             1.04 패스워드 파일 보호                 ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"                  >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
then
	if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]
	then
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있지 않습니다. (취약)"                  >> $HOSTNAME.sol.result.txt 2>&1
		
	else
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있습니다. (양호)"                       >> $HOSTNAME.sol.result.txt 2>&1
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ /etc/passwd 파일이 없습니다."                                                       >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "     	                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
echo Result=`awk -F: '$2=="x"' /etc/passwd | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`		       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0104 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0105 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################           root 이외의 UID가 '0' 금지            ###################"
echo "###################          1.05 root 이외의 UID가 '0' 금지            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: root 계정만이 UID가 0이면 양호"                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                       >> $HOSTNAME.sol.result.txt 2>&1
else
  echo "☞ /etc/passwd 파일이 존재하지 않습니다."                                              >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo Result=`awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0105 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0106 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################               root 계정 su 제한                 ###################"
echo "###################              1.06 root 계정 su 제한                 ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: su 명령 파일의 권한이 4750 이고 특정 그룹만 사용 할 수 있도록 제한 되어있으면 양호" >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① su 사용권한"                                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `which su | grep -v 'no ' | wc -l` -eq 0 ]
then
	echo "su 명령 파일을 찾을 수 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
else
	sucommand=`which su`;
	ls -alL $sucommand                                                                           >> $HOSTNAME.sol.result.txt 2>&1
	sugroup=`ls -alL $sucommand | awk '{print $4}'`;
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② su 명령그룹"                                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `grep -i "^$sugroup:" /etc/group | wc -l` -eq 0 ]
then
	echo "su 명령 그룹을 찾을 수 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
else
	grep -i "^$sugroup:" /etc/group                                                              >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0106 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0107 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################            패스워드 최소 길이 설정              ###################"
echo "###################           1.07 패스워드 최소 길이 설정              ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호"                          >> $HOSTNAME.sol.result.txt 2>&1 
echo "■       : (PASSLENGTH = 8 이상 - 양호)"                                                  >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/passwd ]
then
  if [ `grep -v '^ *#' /etc/default/passwd | grep -i "PASSLENGTH" | wc -l` -gt 0 ]
  then
    grep -v '^ *#' /etc/default/passwd | grep -i "PASSLENGTH"                                  >> $HOSTNAME.sol.result.txt 2>&1
    if [ `grep -v '^ *#' /etc/default/passwd | grep -i "PASSLENGTH" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`=null ]
    then
    	flag="F"
    else
    	flag=`grep -v '^ *#' /etc/default/passwd | grep -i "PASSLENGTH" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`
    fi
   else
    echo "PASSLENGTH 설정이 없습니다.(Default 6자리 )"                                         >> $HOSTNAME.sol.result.txt 2>&1
   	flag="F"
   fi
else
  echo "/etc/default/passwd 파일이 없습니다."                                                  >> $HOSTNAME.sol.result.txt 2>&1
  flag="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0107 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0108 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################         패스워드 최대 사용 기간 설정            ###################"
echo "###################        1.08 패스워드 최대 사용 기간 설정            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패스워드 최대 사용 기간이 12주 이하로 설정되어 있으면 양호"                    >> $HOSTNAME.sol.result.txt 2>&1 
echo "■       : (MAXWEEKS = 12 이하 - 양호)"                                                   >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/passwd ]
then
  grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS"                                      >> $HOSTNAME.sol.result.txt 2>&1
  
	if [ `grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS" | wc -l` -gt 0 ]
  then
    grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS"                                    >> $HOSTNAME.sol.result.txt 2>&1
    if [ `grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`=null ]
    then
    	flag="F"
    else
    	flag=`grep -v '^ *#' /etc/default/passwd | grep -i "MAXWEEKS" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`
    fi
  else
    echo "MAXWEEKS 설정이 없습니다."								                                           >> $HOSTNAME.sol.result.txt 2>&1
   	flag="F"
   fi
else
  echo "/etc/default/passwd 파일이 없습니다."                                                  >> $HOSTNAME.sol.result.txt 2>&1
  flag="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0108 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0109 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################         패스워드 최소 사용 기간 설정            ###################"
echo "###################        1.09 패스워드 최소 사용 기간 설정            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패스워드 최소 사용기간이 1주 이상으로 설정되어 있으면 양호"                      >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (MINWEEKS = 1 이상 - 양호)"                                                    >> $HOSTNAME.sol.result.txt 2>&1 
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/passwd ]
then
  grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS"                                      >> $HOSTNAME.sol.result.txt 2>&1
  
  if [ `grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS" | wc -l` -gt 0 ]
  then
    grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS"                                    >> $HOSTNAME.sol.result.txt 2>&1
    if [ `grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`=null ]
    then
    	flag="F"
    else
      flag=`grep -v '^ *#' /etc/default/passwd | grep -i "MINWEEKS" | awk -F"=" '{print $2}' | sed -e 's/^ *//g' -e 's/ *$//g'`
     fi
  else
    echo "MINWEEKS 설정이 없습니다."								                                           >> $HOSTNAME.sol.result.txt 2>&1
   	flag="F"
   fi
   
else
  echo "/etc/default/passwd 파일이 없습니다."                                                  >> $HOSTNAME.sol.result.txt 2>&1
  flag="Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0109 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0110 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################              불필요한 계정 제거               ###################"
echo "#####################             1.10 불필요한 계정 제거               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 계정이 존재하지 않는 경우 양호"							                           >> $HOSTNAME.sol.result.txt 2>&1
echo "■     : /etc/passwd 파일 내용을 참고하여 불필요한 계정 식별 (인터뷰 필요)"               >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/passwd 파일 내용"                          							                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
    cat /etc/passwd                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0110 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0111 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################         관리자 그룹에 최소한의 계정 포함        ###################"
echo "###################        1.11 관리자 그룹에 최소한의 계정 포함        ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"             >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① 관리자 계정"                                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                       >> $HOSTNAME.sol.result.txt 2>&1
else
  echo "/etc/passwd 파일이 없습니다."                                                          >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 관리자 계정이 포함된 그룹 확인"                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
for group in `awk -F: '$3==0 { print $1}' /etc/passwd`
do
	cat /etc/group | grep "$group"                                                               >> $HOSTNAME.sol.result.txt 2>&1
done
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0111 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0112 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################           계정이 존재하지 않는 GID 금지         ###################"
echo "###################          1.12 계정이 존재하지 않는 GID 금지         ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 구성원이 존재하지 않는 빈 그룹이 발견되지 않을 경우 양호"                        >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 구성원이 존재하지 않는 그룹"                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1

	for gid in `awk -F: '$4==null {print $3}' /etc/group`
	do
		if [ `grep -c $gid /etc/passwd` -eq 0 ]
		then
			grep $gid /etc/group                                                                     > nullgid.txt
		fi		
	done

if [ `cat nullgid.txt | wc -l` -eq 0 ]
then
		echo "구성원이 존재하지 않는 그룹이 발견되지 않았습니다."                                  >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo Result=0                                                                              >> $HOSTNAME.sol.result.txt 2>&1

else
		cat nullgid.txt                                                                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo Result=`cat nullgid.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`                    >> $HOSTNAME.sol.result.txt 2>&1
fi

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0112 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf nullgid.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0113 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                  동일한 UID 금지                ###################"
echo "###################                 1.13 동일한 UID 금지                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"                              >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 동일한 UID를 사용하는 계정 "                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       > total-equaluid.txt
for uid in `cat /etc/passwd | awk -F: '{print $3}'`
do
	cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }'                     > equaluid.txt
	if [ `cat equaluid.txt | wc -l` -gt 1 ]
	then
		cat equaluid.txt                                                                           >> total-equaluid.txt
	fi
done
if [ `sort -k 1 total-equaluid.txt | wc -l` -gt 1 ]
then
	sort -k 1 total-equaluid.txt | uniq -d                                                       >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다."                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=`sort -k 1 total-equaluid.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`         >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0113 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf equaluid.txt
rm -rf total-equaluid.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0114 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                사용자 Shell 점검                ###################"
echo "###################               1.14 사용자 Shell 점검                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 로그인이 필요하지 않은 시스템 계정에 /usr/bin/false 쉘이 부여되어 있으면 양호"   >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 로그인이 필요하지 않은 시스템 계정 확인"                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" > temp114.txt
    cat temp114.txt																																						 >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
   	echo Result=`egrep -v "nologin|false" temp114.txt | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'` >> $HOSTNAME.sol.result.txt 2>&1
  else
    echo "/etc/passwd 파일이 없습니다."                                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0114 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf temp114.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0115 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             Session Timeout 설정                ###################"
echo "###################            1.15 Session Timeout 설정                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: TMOUT=600 / autologout=10 이상으로 설정되어 있으면 양호"			       >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 현재 로그인 계정 설정"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ `set | egrep -i "TMOUT|autologout" | wc -l` -gt 0 ]
then
	if [ `set | egrep -i "TMOUT" | wc -l` -gt 0 ]
		then
			set | egrep -i "TMOUT"                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ TMOUT 설정 확인(/etc/profile)"                                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/profile ]
then
  if [ `cat /etc/profile | grep -i TMOUT | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/profile | grep -i TMOUT | grep -v "^#"                                            >> $HOSTNAME.sol.result.txt 2>&1
  else
  	echo "TMOUT 이 설정되어 있지 않습니다."                                                    >> $HOSTNAME.sol.result.txt 2>&1
  fi
else
  echo "/etc/profile 파일이 없습니다."                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi

else
	set | egrep -i "autologout"                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ autologout 설정 확인(/etc/.login)"                                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/.login ]
then
  if [ `cat /etc/.login | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/.login | grep -i autologout | grep -v "^#"                                            >> $HOSTNAME.sol.result.txt 2>&1
  else
  	echo "autologout 이 설정되어 있지 않습니다."                                                    >> $HOSTNAME.sol.result.txt 2>&1
  fi
else
  echo "/etc/.login 파일이 없습니다."                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

fi
else
	echo "TMOUT 이 설정되어 있지 않습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ login 설정 확인(/etc/default/login)"                                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/login ]
then
  if [ `cat /etc/default/login | grep -i TIMEOUT | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/default/login | grep -i TIMEOUT | grep -v "^#"                                            >> $HOSTNAME.sol.result.txt 2>&1
  else
  	echo "TIMEOUT 이 설정되어 있지 않습니다."                                                    >> $HOSTNAME.sol.result.txt 2>&1
  fi
else
  echo "/etc/default/login 파일이 없습니다."                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0115 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1


echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##########################   2. 파일 및 디렉토리 관리    ##############################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0201 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################      root 홈, 패스 디렉터리 권한 및 패스 설정   ###################"
echo "###################     2.01 root 홈, 패스 디렉터리 권한 및 패스 설정   ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: Path 설정에 “.” 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"                >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ PATH 설정 확인"                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo $PATH                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0201 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0202 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################           파일 및 디렉터리 소유자 설정          ###################"
echo "###################          2.02 파일 및 디렉터리 소유자 설정          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 소유자가 존재하지 않은 파일 및 디렉토리가 존재하지 않을 경우 양호"               >> $HOSTNAME.sol.result.txt 2>&1
echo "■ ※ 실제 소유자명이 숫자(UID)처럼 보일 수 있으므로 담당자 확인 필수"		               >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -d /etc ]
then
  find /etc -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" > 1.17.txt
fi
if [ -d /var ]
then
find /var -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /tmp ]
then
find /tmp -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /home ]
then
find /home -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /export ]
then
find /export -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi

if [ -s 1.17.txt ]
then
	linecount=`cat 1.17.txt | wc -l`
	if [ $linecount -gt 10 ]
  then
		echo "소유자가 존재하지 않는 파일 (상위 10개)"                                             >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  head -10 1.17.txt                                                                          >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo " 등 총 "$linecount"개 파일 존재 (전체 목록은 스크립트 결과 파일 확인)"               >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo Result=$linecount                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0202 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		
	else
		echo "소유자가 존재하지 않는 파일"                                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  cat 1.17.txt                                                                               >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo " 총 "$linecount"개 파일 존재"                                                        >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo Result=$linecount                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0202 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
  echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
  echo "소유자가 존재하지 않는 파일이 발견되지 않았습니다."                                    >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                 	                                                                   >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=0						                                                                     >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "0202 END"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0203 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################        /etc/passwd 파일 소유자 및 권한 설정     ###################"
echo "###################       2.03 /etc/passwd 파일 소유자 및 권한 설정     ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이면 양호"                     >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
then
  ls -alL /etc/passwd                                                                          >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/passwd | awk -F" " '{print $3 ":" $1 }'`                >> $HOSTNAME.sol.result.txt 2>&1
else
  echo "☞ /etc/passwd 파일이 없습니다."                                                       >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null" 																											               >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0203 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0204 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################        /etc/shadow 파일 소유자 및 권한 설정     ###################"
echo "###################       2.04 /etc/shadow 파일 소유자 및 권한 설정     ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이면 양호"                     >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow                                                                          >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/shadow | awk -F" " '{print $3 ":" $1 }'`                >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ /etc/shadow 파일이 없습니다."                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																											                 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0204 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0205 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################        /etc/hosts 파일 소유자 및 권한 설정      ###################"
echo "###################       2.05 /etc/hosts 파일 소유자 및 권한 설정      ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 600 이면 양호"                      >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/hosts ]
then
  ls -alL /etc/hosts                                                                           >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/hosts | awk -F" " '{print $3 ":" $1 }'`           							       >> $HOSTNAME.sol.result.txt 2>&1
 else
  echo "☞ /etc/hosts 파일이 없습니다."                                                        >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                             	       >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																																			 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0205 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0206 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################  /etc/(x)inetd.conf 파일 소유자 및 권한 설정    ###################"
echo "################### 2.06 /etc/(x)inetd.conf 파일 소유자 및 권한 설정    ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/inetd.conf 파일의 소유자가 root 이고, 권한이 600 이면 양호"                 >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/inetd.conf ]
then
	ls -alL /etc/inetd.conf                                                                  	   >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                	   >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/inetd.conf | awk -F" " '{print $3 ":" $1 }'`   				 >> $HOSTNAME.sol.result.txt 2>&1
elif [ -f /etc/xinetd.conf ]
then
	ls -alL /etc/xinetd.conf                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/xinetd.conf | awk -F" " '{print $3 ":" $1 }'`   				 >> $HOSTNAME.sol.result.txt 2>&1

else
  echo "☞ /etc/(x)inetd.conf 파일이 없습니다."                                          	     >> $HOSTNAME.sol.result.txt 2>&1
 	echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																														   				 >> $HOSTNAME.sol.result.txt 2>&1

fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0206 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0207 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################    /etc/syslog.conf 파일 소유자 및 권한 설정    ###################"
echo "###################   2.07 /etc/syslog.conf 파일 소유자 및 권한 설정    ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/(r)syslog.conf 파일의 소유자가 root이고 권한이 644 이면 양호"                  >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/syslog.conf ]
then
	ls -alL /etc/syslog.conf                                                                   >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/syslog.conf | awk -F" " '{print $3 ":" $1 }'`   				 >> $HOSTNAME.sol.result.txt 2>&1

elif [ -f /etc/rsyslog.conf ]
then
	ls -alL /etc/rsyslog.conf                                                                  >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/rsyslog.conf | awk -F" " '{print $3 ":" $1 }'`   				 >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ /etc/(r)syslog.conf 파일이 없습니다."                                             >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																														   				 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0207 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0208 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################    /etc/services 파일 소유자 및 권한 설정       ###################"
echo "###################   2.08 /etc/services 파일 소유자 및 권한 설정       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/services 파일의 소유자가 root이고 권한이 644 이면 양호"                     >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/services ]
then
  ls -alL /etc/services                                                                        >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/services | awk -F" " '{print $3 ":" $1 }'`   					 >> $HOSTNAME.sol.result.txt 2>&1
 else
  echo "☞ /etc/services 파일이 없습니다."                                                     >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                               	     >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																														   				 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0208 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0209 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################       SUID,SGID,Sticky bit 설정 파일 점검       ###################"
echo "###################      2.09 SUID,SGID,Sticky bit 설정 파일 점검       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"                               >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
find /usr -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;        > 1.24.txt 2> /dev/null
if [ -s 1.24.txt ]
then
	linecount=`cat 1.24.txt | wc -l`
	if [ $linecount -gt 10 ]
  then
  	echo "SUID,SGID,Sticky bit 설정 파일 (상위 10개)"                                          >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  head -10 1.24.txt                                                                          >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo " 등 총 "$linecount"개 파일 존재 (전체 목록은 스크립트 결과 파일 확인)"               >> $HOSTNAME.sol.result.txt 2>&1
  	echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo Result=`echo $linecount | sed -e 's/^ *//g' -e 's/ *$//g'`                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0209 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		
	else
  	echo "SUID,SGID,Sticky bit 설정 파일"                                                      >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  cat 1.24.txt                                                                               >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo " 총 "$linecount"개 파일 존재"                                                        >> $HOSTNAME.sol.result.txt 2>&1
  	echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo Result=`echo $linecount | sed -e 's/^ *//g' -e 's/ *$//g'`                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0209 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1		
  fi
else
	echo "☞ SUID/SGID로 설정된 파일이 발견되지 않았습니다."                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                 	                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=0						                                                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0210 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#############   사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정   #############"
echo "#############  2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정   #############" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고"        >> $HOSTNAME.sol.result.txt 2>&1
echo "      : 홈디렉터리 환경변수 파일에 소유자 이외에 쓰기 권한이 제거되어 있으면 양호"       >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 홈디렉터리 환경변수 파일"                                                             >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
do
  FILE=/$file
  if [ -f $FILE ]
  then
    ls -alL $FILE                                                                              >> $HOSTNAME.sol.result.txt 2>&1
  fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
    then
      ls -alL $FILE                                                                            >> $HOSTNAME.sol.result.txt 2>&1
    fi
  done
done
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0210 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0211 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             world writable 파일 점검            ###################"
echo "###################            1.11 world writable 파일 점검            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"            >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -d /etc ]
then
  find /etc -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"         > world-writable.txt
fi
if [ -d /var ]
then
  find /var -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"         >> world-writable.txt
fi
if [ -d /tmp ]
then
  find /tmp -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"         >> world-writable.txt
fi
if [ -d /home ]
then
  find /home -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}'| grep -v "^l"         >> world-writable.txt
fi
if [ -d /export ]
then
  find /export -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}'| grep -v "^l"       >> world-writable.txt
fi

if [ -s world-writable.txt ]
then
  linecount=`cat world-writable.txt | wc -l`
  if [ $linecount -gt 10 ]
  then
  	echo "World Writable 파일 (상위 10개)"                                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  head -10 world-writable.txt                                                                >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo " 등 총 "$linecount"개 파일 존재 (전체 목록은 스크립트 결과 파일  확인)"              >> $HOSTNAME.sol.result.txt 2>&1
  	echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo Result=`echo $linecount | sed -e 's/^ *//g' -e 's/ *$//g'`                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0211 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
	else
    echo "World Writable 파일"                                                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
	  cat world-writable.txt                                                                     >> $HOSTNAME.sol.result.txt 2>&1
    echo " 총 "$linecount"개 파일 존재"                                                        >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo Result=`echo $linecount | sed -e 's/^ *//g' -e 's/ *$//g'`                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "0211 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
    echo "☞ World Writable 권한이 부여된 파일이 발견되지 않았습니다."                         >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
  	echo Result=0					                                                                     >> $HOSTNAME.sol.result.txt 2>&1
    echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
    echo "0211 END"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0212 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################     /dev에 존재하지 않는 device 파일 점검       ###################"
echo "###################    2.12 /dev에 존재하지 않는 device 파일 점검       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준 : dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■        : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)"                  >> $HOSTNAME.sol.result.txt 2>&1
echo "■        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
find /dev -type f -exec ls -l {} \;                                                            > 1.32.txt

if [ -s 1.32.txt ]
then
	cat 1.32.txt                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다."                            >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0212 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf 1.32.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0213 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################       HOME/.rhosts, hosts.equiv 사용 금지       ###################"
echo "###################      2.13 HOME/.rhosts, hosts.equiv 사용 금지       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인"          >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                   > 1.33.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                   >> 1.33.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                   >> 1.33.txt
fi

if [ -s 1.33.txt ]
then
	cat 1.33.txt | grep -v '^ *$'                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="M/T"
else
	echo "☞ r-command Service Disable"                                                          >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "③ /etc/hosts.equiv 파일 설정"                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/hosts.equiv ]
	then
		echo "(1) Permission: (`ls -al /etc/hosts.equiv`)"                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo "(2) 설정 내용:"                                                                      >> $HOSTNAME.sol.result.txt 2>&1
		echo "----------------------------------------"                                            >> $HOSTNAME.sol.result.txt 2>&1
		if [ `cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
		then
			cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$'                                      >> $HOSTNAME.sol.result.txt 2>&1
		else
			echo "설정 내용이 없습니다."                                                             >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		echo "/etc/hosts.equiv 파일이 없습니다."                                                   >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "④ 사용자 home directory .rhosts 설정 내용"                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

for dir in $HOMEDIRS
do
	for file in $FILES
	do
		if [ -f $dir$file ]
		then
			echo " "                                                                                 > rhosts.txt
			echo "# $dir$file 파일 설정:"                                                            >> $HOSTNAME.sol.result.txt 2>&1
			echo "(1) Permission: (`ls -al $dir$file`)"                                              >> $HOSTNAME.sol.result.txt 2>&1
			echo "(2) 설정 내용:"                                                                    >> $HOSTNAME.sol.result.txt 2>&1
			echo "----------------------------------------"                                          >> $HOSTNAME.sol.result.txt 2>&1
			if [ `cat $dir$file | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
			then
				cat $dir$file | grep -v "#" | grep -v '^ *$'                                           >> $HOSTNAME.sol.result.txt 2>&1
			else
				echo "설정 내용이 없습니다."                                                           >> $HOSTNAME.sol.result.txt 2>&1
			fi
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		fi
	done
done
if [ ! -f rhosts.txt ]
then
	echo ".rhosts 파일이 없습니다."                                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0213 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf rhosts.txt
rm -rf 1.33.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0214 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                접속 IP 및 포트 제한             ###################"
echo "###################               2.14 접속 IP 및 포트 제한             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/hosts.deny 파일에 All Deny(ALL:ALL) 설정이 등록되어 있고,"                  >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : /etc/hosts.allow 파일에 접근 허용 IP가 등록되어 있으면 양호"                   >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/hosts.allow 파일 설정"                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/hosts.allow ]
then
	if [ ! `cat /etc/hosts.allow | grep -v "#" | grep -v '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.allow | grep -v "#" | grep -v '^ *$'                                        >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/hosts.allow 파일이 없습니다."                                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② /etc/hosts.deny 파일 설정"                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/hosts.deny ]
then
	if [ ! `cat /etc/hosts.deny | grep -v "#" | grep -v '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.deny | grep -v "#" | grep -v '^ *$'                                         >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/hosts.deny 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0214 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0215 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################       host.lpd 파일 소유자 및 권한 설정         ###################"
echo "###################      2.15 host.lpd 파일 소유자 및 권한 설정         ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이면 양호"                   >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/host.lpd ]
then
	ls -alL /etc/host.lpd                                                                        >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                         	        	 >> $HOSTNAME.sol.result.txt 2>&1
  echo Result=`perm /etc/host.lpd | awk -F" " '{print $3 ":" $1 }'` 			 		   >> $HOSTNAME.sol.result.txt 2>&1
 else
  echo "☞ /etc/host.lpd 파일이 없습니다. (양호)"                                              >> $HOSTNAME.sol.result.txt 2>&1
  echo " "                                                                         	        	 >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Null:Null"																													 			 		   >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0215 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0216 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                 NIS 서비스 비활성화             ###################"
echo "###################                2.16 NIS 서비스 비활성화             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 NIS 서비스가 비활성화 되어있는 경우"                                 >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nids"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ NIS, NIS+ Service Disable"                                                          >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                          	               	         >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="Disabled"																						 			 			   	           >> $HOSTNAME.sol.result.txt 2>&1
else
	ps -ef | egrep $SERVICE | grep -v "grep"                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                          	               	         >> $HOSTNAME.sol.result.txt 2>&1
  echo Result="M/T"																							 			 			   	           >> $HOSTNAME.sol.result.txt 2>&1

fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0216 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0217 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                   UMASK 설정 관리               ###################"
echo "###################                  2.17 UMASK 설정 관리               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: UMASK 값이 022이면 양호"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (UMASK 값은 /etc/profile과 /etc/default/login 파일에서 설정함)"                >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (둘 다 설정되어 있을 경우 /etc/profile 파일의 설정을 적용받음)"                >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 현재 로그인 계정 UMASK"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
umask                                                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/profile 파일(올바른 설정: umask 022)"                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/profile ]
then
  if [ `cat /etc/profile | grep -i umask | grep -v "^#" | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -A 1 -B 1 -i umask |grep -v "^#"																	 >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "umask 설정이 없습니다."                                                              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
  echo "/etc/profile 파일이 없습니다."                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② /etc/default/login 파일"                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------"                                        >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/login ]
then
	if [ `cat /etc/default/login | grep -i "umask" | grep "=" | wc -l` -gt 0 ]
	then
  	cat 	/etc/default/login | grep -A 1 -B 1 -i "umask" | grep "="                            >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "umask 설정이 없습니다."                                                              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
  echo "/etc/default/login 파일이 없습니다."                                                   >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                             >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0217 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0218 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################           홈 디렉토리 소유자 및 권한 설정       ###################"
echo "###################          2.18 홈 디렉토리 소유자 및 권한 설정       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고,"   >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"                                 >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 사용자 홈 디렉터리"                                                                   >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
		ls -dal $dir | grep '\d.........'                                                          >> $HOSTNAME.sol.result.txt 2>&1
	fi
done
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0218 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0219 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################     홈 디렉토리로 지정한 디렉토리의 존재 관리   ###################"
echo "###################    2.19 홈 디렉토리로 지정한 디렉토리의 존재 관리   ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호"                         >> $HOSTNAME.sol.result.txt 2>&1
# 홈 디렉토리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
# 예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음.
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 홈 디렉터리가 존재하지 않은 계정"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
	then
		awk -F: '$6=="'${dir}'" { print "● 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd        >> $HOSTNAME.sol.result.txt 2>&1
		flag=`expr $flag + 1`
		echo " "                                                                                   > 1.29.txt
	fi
done

if [ ! -f 1.29.txt ]
then
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되지 않았습니다. (양호)"                        >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=0                                                                                >> $HOSTNAME.sol.result.txt 2>&1
else
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0219 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf 1.29.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0220 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################       숨겨진 파일 및 디렉토리 검색 및 제거      ###################"
echo "###################      2.20 숨겨진 파일 및 디렉토리 검색 및 제거      ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 디렉토리 내에 숨겨진 파일을 확인 및 검색 하여 , 불필요한 파일 존재 경우 삭제 했을 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
find /tmp -name ".*" -ls                                                                       >> $HOSTNAME.sol.result.txt 2>&1
find /home -name ".*" -ls                                                                      >> $HOSTNAME.sol.result.txt 2>&1
find /usr -name ".*" -ls                                                                       >> $HOSTNAME.sol.result.txt 2>&1
find /var -name ".*" -ls                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "위에 리스트에서 숨겨진 파일 확인"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0220 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##############################    3. 서비스 관리     ##################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0301 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              finger 서비스 비활성화             ###################"
echo "###################             3.01 finger 서비스 비활성화             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: Finger 서비스가 비활성화 되어 있을 경우 양호"                                    >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -eq 0 ]
	then
		echo "☞ Finger Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
		flag="Disabled"
	else
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=`netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`  >> $HOSTNAME.sol.result.txt 2>&1
else
	if [ `netstat -na | grep "*.79 " | grep -i "LISTEN" | head -1 | wc -l` -eq 0 ]
	then
		echo "☞ Finger Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
	else
		netstat -na | grep "*.79 " | grep -i "LISTEN" | head -1                                    >> $HOSTNAME.sol.result.txt 2>&1
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=`netstat -na | grep "*.79 " | grep -i "LISTEN" | head -1 | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`  >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0301 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0302 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              Anonymous FTP 비활성화             ###################"
echo "###################             3.02 Anonymous FTP 비활성화             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호"                            >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호"  >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(2)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(2)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(3)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(3)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -na | grep "*.21 " | grep -i "LISTEN" | head -1                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
fi
################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
	flag1="Enabled"

	echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo "③ Anonymous FTP 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
	if [ -s vsftpd.txt ]
	then
		cat $vsfile | grep -i "anonymous_enable" | awk '{print "● VsFTP 설정: " $0}'                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $vsfile | grep -i "anonymous_enable" | grep -i "YES" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	else
		if [ `cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l` -gt 0 ]
		then
			echo "● ProFTP, 기본FTP 설정:"                                                               >> $HOSTNAME.sol.result.txt 2>&1
			cat /etc/passwd | egrep "^ftp:|^anonymous:"                                                  >> $HOSTNAME.sol.result.txt 2>&1
			echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
			flag2=`cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
			echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		else
			echo "● ProFTP, 기본FTP 설정: /etc/passwd 파일에 ftp 또는 anonymous 계정이 없습니다."        >> $HOSTNAME.sol.result.txt 2>&1
			echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
			flag2=`cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
		fi
	fi
else
	echo "☞ FTP Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0302 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0303 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              r 계열 서비스 비활성화             ###################"
echo "###################             3.03 r 계열 서비스 비활성화             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"                             >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ -f rcommand.txt ]
then
	rm -rf rcommand.txt
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="Enabled"										 																									   >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ r-commands Service Disable"                                                         >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="Disabled"										 																									   >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0303 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0304 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################          cron 파일 소유자 및 권한 설정          ###################"
echo "###################         3.04 cron 파일 소유자 및 권한 설정          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: cron.allow 또는 cron.deny 파일 권한이 640 이하이고 소유자가 root일 경우 양호"    >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① cron.allow 파일 권한 확인"                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/cron.d/cron.allow ]
then
	ls -alL /etc/cron.d/cron.allow                                                               >> $HOSTNAME.sol.result.txt 2>&1
	flag1=`perm /etc/cron.d/cron.allow | awk -F" " '{print $3 ":" $1 }'`
else
	echo "/etc/cron.d/cron.allow 파일이 없습니다."                                               >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Null:Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② cron.deny 파일 권한 확인"                                                             >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/cron.d/cron.deny ]
then
	ls -alL /etc/cron.d/cron.deny                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag2=`perm /etc/cron.d/cron.deny | awk -F" " '{print $3 ":" $1 }'`
else
	echo "/etc/cron.d/cron.deny 파일이 없습니다."                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag2="Null:Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0304 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0305 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################         Dos 공격에 취약한 서비스 비활성화       ###################"
echo "###################        3.05 Dos 공격에 취약한 서비스 비활성화       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: DoS 공격에 취약한 echo , discard , daytime , chargen 서비스를 사용하지 않았을 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "tcp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "udp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp"                 >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp"                 >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"                             >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | head -1                                                    >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | head -1                                                    >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | head -1                                                    >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | head -1                                                    >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi

if [ -f unnecessary.txt ]
then
	rm -rf unnecessary.txt
	flag="Enabled"
else
	echo "불필요한 서비스가 동작하고 있지 않습니다.(echo, discard, daytime, chargen)"            >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0305 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0306 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################               NFS 서비스 비활성화               ###################"
echo "###################              3.06 NFS 서비스 비활성화               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 제거되어 있는 경우 양호"                         >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $HOSTNAME.sol.result.txt 2>&1
   flag1="Enabled_Server"
 else
   echo "☞ NFS Service Disable"                                                               >> $HOSTNAME.sol.result.txt 2>&1
   flag1="Disabled_Server"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② NFS Client Daemon(statd,lockd)확인"                                                   >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd" | wc -l` -gt 0 ] 
  then
    ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd"                    >> $HOSTNAME.sol.result.txt 2>&1
    flag2="Enabled_Client"
  else
    echo "☞ NFS Client(statd,lockd) Disable"                                                  >> $HOSTNAME.sol.result.txt 2>&1
    flag2="Disabled_Client"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0306 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0307 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                   NFS 접근 통제                 ###################"
echo "###################                  3.07 NFS 접근 통제                 ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준1: NFS 서버 데몬이 동작하지 않으면 양호"                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준2: NFS 서버 데몬이 동작하는 경우 /etc/dfs/dfstab 파일에 everyone 공유 설정이 없으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $HOSTNAME.sol.result.txt 2>&1
   flag="M/T"
 else
   echo "☞ NFS Service Disable"                                                               >> $HOSTNAME.sol.result.txt 2>&1
   flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② /etc/dfs/dfstab 파일 설정"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/dfs/dfstab ]
then
	if [ `cat /etc/dfs/dfstab | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/dfs/dfstab | grep -v "^#" | grep -v "^ *$"                                        >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
  echo "/etc/dfs/dfstab 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0307 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0308 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                  automountd 제거                ###################"
echo "###################                 3.08 automountd 제거                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: automountd 서비스가 동작하지 않을 경우 양호"                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① Automountd Daemon 확인"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] 
 then
   ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"              >> $HOSTNAME.sol.result.txt 2>&1
   flag="Enabled"
 else
   echo "☞ Automountd Daemon Disable"                                                         >> $HOSTNAME.sol.result.txt 2>&1
   flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0308 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0309 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                  RPC 서비스 확인                ###################"
echo "###################                 3.09 RPC 서비스 확인                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 불필요한 rpc 관련 서비스가 존재하지 않으면 양호"                                 >> $HOSTNAME.sol.result.txt 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

echo "☞ 불필요한 RPC 서비스 동작 확인"                                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -gt 0 ]
then
 cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD                                   >> $HOSTNAME.sol.result.txt 2>&1
else
 echo "불필요한 RPC 서비스가 존재하지 않습니다."                                               >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=`cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0309 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0310 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                  NIS , NIS+ 점검                ###################"
echo "###################                 3.10 NIS , NIS+ 점검                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우 양호"            >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nids"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ NIS, NIS+ Service Disable"                                                        >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
else
	echo "☞ NIS+ 데몬은 rpc.nids임"														   >> $HOSTNAME.sol.result.txt 2>&1
	ps -ef | egrep $SERVICE | grep -v "grep"                                                   >> $HOSTNAME.sol.result.txt 2>&1
	if [ `ps -ef | grep "rpc.nids" | grep -v "grep" | wc -l` -eq 0 ]
	then
		flag="Enabled"
	else
		flag="nis+"
	fi
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0310 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0311 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             tftp, talk 서비스 비활성화          ###################"
echo "###################            3.11 tftp, talk 서비스 비활성화          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우에 양호"                         >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp"                    >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp"                    >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "  " $2}' | grep "udp"                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "idle" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "idle" | head -1                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "idle" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "idle" | head -1                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "idle" | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "idle" | head -1                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi

if [ -f 1.56.txt ]
then
	rm -rf 1.56.txt
	flag="Enabled"
else
	echo "☞ tftp, talk, ntalk Service Disable"                                                  >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0311 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0312 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##################                  Sendmail 버전 점검               ##################"
echo "##################                 3.12 Sendmail 버전 점검               ##################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: sendmail 버전이 8.13.8 이상이면 양호"                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	flag="M/T"
	ps -ef | grep sendmail | grep -v grep																			                   >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                  	 >> $HOSTNAME.sol.result.txt 2>&1
	
	echo "② sendmail 버전확인"                                                                  >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	   then
	     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ                                          >> $HOSTNAME.sol.result.txt 2>&1
	   else
	     echo "/etc/mail/sendmail.cf 파일이 없습니다."                                           >> $HOSTNAME.sol.result.txt 2>&1
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고]"                                                                              	   >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "/etc/services 파일에서 포트 확인"                                                     	 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "서비스 포트 활성화 여부 확인"                                                        		 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port" | wc -l` -gt 0 ]
	then
		echo "● $port번 포트 netstat확인"							   						  >> $HOSTNAME.sol.result.txt 2>&1
		netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port"                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "● ps명령어 sendmail확인"							     						  >> $HOSTNAME.sol.result.txt 2>&1		
		ps -ef | grep -i "sendmail"								     						  >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		
		if [ `uname -r | awk -F"." '{print $2}'` -ge 10 ]
		then
			echo "● svcs명령어 sendmail 확인"					                          >> $HOSTNAME.sol.result.txt 2>&1
			svcs sendmail | grep -i "^online"			                                  >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		echo "☞ Sendmail Service Disable"                                                         >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "서비스 포트 확인 불가" 				                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0312 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0313 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##################                 스팸 메일 릴레이 제한             ##################"
echo "##################                3.13 스팸 메일 릴레이 제한             ##################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (R$*         $#error $@ 5.7.1 $: "550 Relaying denied" 해당 설정에 주석이 제거되어 있으면 양호)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	flag1="Enabled"
	ps -ef | grep sendmail | grep -v grep																			                   >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                  	 >> $HOSTNAME.sol.result.txt 2>&1
	
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "② /etc/mail/sendmail.cf 파일의 옵션 확인"                                             >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
	    cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"                         >> $HOSTNAME.sol.result.txt 2>&1
	    flag2=`cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" | grep -v ^# | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	  else
	    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                            >> $HOSTNAME.sol.result.txt 2>&1
	    flag2="Null"
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고]"                                                                              	   >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "/etc/services 파일에서 포트 확인"                                                     	 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "서비스 포트 활성화 여부 확인"                                                        		 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port" | wc -l` -gt 0 ]
	then
		echo "● $port번 포트 netstat확인"							   						  >> $HOSTNAME.sol.result.txt 2>&1
		netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port"                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "● ps명령어 sendmail확인"							     						  >> $HOSTNAME.sol.result.txt 2>&1		
		ps -ef | grep -i "sendmail"								     						  >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		
		if [ `uname -r | awk -F"." '{print $2}'` -ge 10 ]
		then
			echo "● svcs명령어 sendmail 확인"					                          >> $HOSTNAME.sol.result.txt 2>&1
			svcs sendmail | grep -i "^online"			                                  >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		echo "☞ Sendmail Service Disable"                                                         >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "서비스 포트 확인 불가" 				                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0313 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0314 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##################            일반사용자의 Sendmail 실행 방지        ##################"
echo "##################           3.14 일반사용자의 Sendmail 실행 방지        ##################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (restrictqrun 옵션이 설정되어 있을 경우 양호)"                                 >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① sendmail 프로세스 확인"                                    					                 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
then
	flag1="Enabled"
	ps -ef | grep sendmail | grep -v grep																			                   >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                  	 >> $HOSTNAME.sol.result.txt 2>&1
	
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "② /etc/mail/sendmail.cf 파일의 옵션 확인"                                             >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
	    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                               >> $HOSTNAME.sol.result.txt 2>&1
	    flag2=`grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep restrictqrun | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	  else
	    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                            >> $HOSTNAME.sol.result.txt 2>&1
	    flag2="Null"
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ Sendmail Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고]"                                                                              	   >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "/etc/services 파일에서 포트 확인"                                                     	 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "서비스 포트 활성화 여부 확인"                                                        		 >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port" | wc -l` -gt 0 ]
	then
		echo "● $port번 포트 netstat확인"							   						  >> $HOSTNAME.sol.result.txt 2>&1
		netstat -na | grep -i "listen" | egrep "\*\.$port|\.$port"                            >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "● ps명령어 sendmail확인"							     						  >> $HOSTNAME.sol.result.txt 2>&1		
		ps -ef | grep -i "sendmail"								     						  >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                              >> $HOSTNAME.sol.result.txt 2>&1
		
		if [ `uname -r | awk -F"." '{print $2}'` -ge 10 ]
		then
			echo "● svcs명령어 sendmail 확인"					                          >> $HOSTNAME.sol.result.txt 2>&1
			svcs sendmail | grep -i "^online"			                                  >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		echo "☞ Sendmail Service Disable"                                                         >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "서비스 포트 확인 불가" 				                                                         >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0314 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


echo "0315 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                DNS 보안 버전 패치               ###################"
echo "###################               3.15 DNS 보안 버전 패치               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호"           >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (양호한 버전: 8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)"            >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
then
	flag="Enabled"
	if [ -f $DNSPR ]
	then
    echo "BIND 버전 확인"                                                                      >> $HOSTNAME.sol.result.txt 2>&1
    echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
    $DNSPR -v | grep BIND                                                                      >> $HOSTNAME.sol.result.txt 2>&1
  else
    echo "$DNSPR 파일이 없습니다."                                                             >> $HOSTNAME.sol.result.txt 2>&1
  fi
else
  echo "☞ DNS Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
  flag="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0315 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0316 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              DNS Zone Transfer 설정             ###################"
echo "###################             3.16 DNS Zone Transfer 설정             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"           >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① DNS 프로세스 확인 " >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ DNS Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
else
	ps -ef | grep named | grep -v "grep"                                                         >> $HOSTNAME.sol.result.txt 2>&1
	flag="M/T"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ `ls -al /etc/rc*.d/* | grep -i named | grep "/S" | wc -l` -gt 0 ]
then
	ls -al /etc/rc*.d/* | grep -i named | grep "/S"                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo "② /etc/named.conf 파일의 allow-transfer 확인"                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/named.conf ]
then
	cat /etc/named.conf | grep 'allow-transfer'                                                  >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "/etc/named.conf 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "③ /etc/named.boot 파일의 xfrnets 확인"                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/named.boot ]
then
	cat /etc/named.boot | grep "\xfrnets"                                                        >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "/etc/named.boot 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0316 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1






echo "0317 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################         Apache 디렉토리 리스팅 제거          ####################"
echo "#####################        3.17 Apache 디렉토리 리스팅 제거          ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	echo "☞ Apache 데몬 확인"                                                         		 >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	echo "☞ $apache_type Service Enable"                                                        >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "☞ $apache_type 설정파일 경로"                                                          		 >> $HOSTNAME.sol.result.txt 2>&1
	if [ -f Inf_apaTemp.txt ]
	then
		cat Inf_apaTemp.txt                                                           			 >> $HOSTNAME.sol.result.txt 2>&1
		rm -rf Inf_apaTemp.txt
	fi
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	echo $ACONF																					 >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	
	if [ -f $ACONF ]
	then
		echo "☞ Indexes 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"    >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#'                   >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#' | grep Indexes | wc -l`
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $HOSTNAME.sol.result.txt 2>&1
		flag2="Null"
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0317 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0318 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################        Apache 웹 프로세스 권한 제한          ####################"
echo "#####################       3.18 Apache 웹 프로세스 권한 제한          ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"      >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1	
	cat $ACONF | grep -i "^user"                                                                 >> $HOSTNAME.sol.result.txt 2>&1
	cat $ACONF | grep -i "^group"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	
	flag2=`cat $ACONF | grep -i "^user" | awk -F" " '{print $2}'`":"`cat $ACONF | grep -i "^group" | awk -F" " '{print $2}'`
	
	if [ $apache_type = "apache2" ]
	then
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		echo "☞ envvars 파일 설정 확인"                                                           >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
		cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^User" | awk '{print $2}' | sed 's/[${}]//g'`  >> $HOSTNAME.sol.result.txt 2>&1	
		cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^Group" | awk '{print $2}' | sed 's/[${}]//g'` >> $HOSTNAME.sol.result.txt 2>&1	
		
		usercheck=`cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^User" | awk '{print $2}' | sed 's/[${}]//g'` | awk -F"=" '{print $2}'`
		groupcheck=`cat $AHOME/envvars | grep -i `cat $ACONF | grep -i "^Group" | awk '{print $2}' | sed 's/[${}]//g'` | awk -F"=" '{print $2}'`
		flag2=$usercheck":"$groupcheck
		
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "☞ $apache_type 데몬 동작 계정 확인"                                                   >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	ps -ef | grep $apache_type | grep -v grep                                                    >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled:Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0318 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0319 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################        Apache 상위 디렉토리 접근 금지        ####################"
echo "#####################       3.19 Apache 상위 디렉토리 접근 금지        ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: $apache_type 설정파일의 Directory 부분의 AllowOverride None 설정이 아니면 양호"  >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#'                 >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#' | grep AllowOverride | awk -F" " '{print $2}' | grep -v none | wc -l`
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $HOSTNAME.sol.result.txt 2>&1
		flag2="Null"
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0319 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0320 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################           Apache 불필요한 파일 제거          ####################"
echo "#####################          3.20 Apache 불필요한 파일 제거          ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준  : Server_Root 또는 DocumentRoot 내 manual 디렉터리가 존재하지 않거나,"           >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : test-cgi, printenv 파일이 존재하지 않는  경우 양호"  									         >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="M/T"
	echo "☞ ServerRoot Directory" 	 	                                                           >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"      	 >> $HOSTNAME.sol.result.txt 2>&1
	echo $AHOME																																									 >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "☞ DocumentRoot Directory" 	                                                           >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"    		 >> $HOSTNAME.sol.result.txt 2>&1
	if [ $apache_type = "httpd" ]
	then
		DOCROOT=`cat $ACONF | grep -i ^DocumentRoot | awk '{print $2}' | sed 's/"//g'` 2>&1
		echo $DOCROOT																																							 >> $HOSTNAME.sol.result.txt 2>&1
	elif [ $apache_type = "apache2" ]
	then
		cat $AHOME/sites-enabled/*.conf | grep -i "DocumentRoot" | awk '{print $2}' | uniq         > apache2_DOCROOT.txt 2>&1
		cat apache2_DOCROOT.txt																																		 >> $HOSTNAME.sol.result.txt 2>&1
	fi
	echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1

	find $AHOME -name "cgi-bin" -exec ls -l {} \;																								 > unnecessary_file.txt 2>&1
	find $AHOME -name "printenv" -exec ls -l {} \;																							 >> unnecessary_file.txt 2>&1
	find $AHOME -name "manual" -exec ls -ld {} \;																								 > unnecessary_directory.txt 2>&1
	
	find $DOCROOT -name "cgi-bin" -exec ls -l {} \;																							 >> unnecessary_file.txt 2>&1
	find $DOCROOT -name "printenv" -exec ls -l {} \;																						 >> unnecessary_file.txt 2>&1
	
	if [ $apache_type = "apache2" ]
	then
		for docroot2 in `cat ./apache2_DOCROOT.txt`
		do
			find $docroot2 -name "cgi-bin" -exec ls -l {} \;																					 >> unnecessary_file.txt 2>&1
			find $docroot2 -name "printenv" -exec ls -l {} \;																					 >> unnecessary_file.txt 2>&1
			find $docroot2 -name "manual" -exec ls -ld {} \;																					 >> unnecessary_directory.txt 2>&1
		done
	fi
	
		echo "☞ test-cgi, printenv 파일 확인"       					                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
		if [ `cat ./unnecessary_file.txt | wc -l` -eq 0 ]
		then
			echo "☞ test-cgi, printenv 파일이 존재하지 않습니다."		                               >> $HOSTNAME.sol.result.txt 2>&1
		else
			cat ./unnecessary_file.txt																															 >> $HOSTNAME.sol.result.txt 2>&1
		fi
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1

		echo "☞ manual 디렉토리 확인"				       					                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
		if [ `cat ./unnecessary_directory.txt | wc -l` -eq 0 ]
		then
			echo "☞ manual 디렉토리가 존재하지 않습니다."		  				                             >> $HOSTNAME.sol.result.txt 2>&1
		else
			cat ./unnecessary_directory.txt																													 >> $HOSTNAME.sol.result.txt 2>&1
		fi
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
rm -rf ./unnecessary_file.txt
rm -rf ./unnecessary_directory.txt
echo "0320 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0321 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################             Apache 링크 사용 금지            ####################"
echo "#####################            3.21 Apache 링크 사용 금지            ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#'                >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $ACONF | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#' | grep FollowSymLinks | wc -l`
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $HOSTNAME.sol.result.txt 2>&1
		flag2="Null"
	fi		
		
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0321 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0322 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################      Apache 파일 업로드 및 다운로드 제한     ####################"
echo "#####################     3.22 Apache 파일 업로드 및 다운로드 제한     ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호"     >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	
	if [ -f $ACONF ]
	then
		echo "☞ $ACONF 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#'              >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                     >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#' | grep LimitRequestBody | wc -l`
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                  >> $HOSTNAME.sol.result.txt 2>&1
		flag2="Null"		
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0322 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0323 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################         Apache 웹 서비스 영역의 분리         ####################"
echo "#####################        3.23 Apache 웹 서비스 영역의 분리         ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: DocumentRoot를 기본 디렉터리가 아닌 별도의 디렉토리로 지정한 경우 양호" 				 >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="M/T"
	echo "☞ DocumentRoot 확인"  		                                                             >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	if [ $apache_type = "httpd" ]
	then
		echo $DOCROOT																																						 	 >> $HOSTNAME.sol.result.txt 2>&1
	elif [ $apache_type = "apache2" ]
	then
		for docroot2 in `cat ./apache2_DOCROOT.txt`
		do
			echo $docroot2																																					 >> $HOSTNAME.sol.result.txt 2>&1
		done
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
rm -rf ./apache2_DOCROOT.txt
echo "0323 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1




echo "0324 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                 ssh 원격접속 허용               ###################"
echo "###################                3.24 ssh 원격접속 허용               ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SSH 서비스가 활성화 되어 있으면 양호"                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① 프로세스 데몬 동작 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $HOSTNAME.sol.result.txt 2>&1
	else
		ps -ef | grep sshd | grep -v "grep"                                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

echo "② 서비스 포트 확인(sshd_config 파일에 포트 설정시 해당 포트가 적용됨)"                  >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo " " > ssh-result.txt
ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep "^Port" | grep -v "^#" | wc -l` -gt 0 ]
		then
			cat $file | grep "^Port" | grep -v "^#" | awk '{print "SSH 설정파일: " $0 " ('${file}')"}'   >> ssh-result.txt
			port1=`cat $file | grep "^Port" | grep -v "^#" | awk '{print $2}'`
			echo " "                                                                                 > port1-search.txt
		else
			echo "SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)"                      >> ssh-result.txt
		fi
	fi
done

if [ `cat ssh-result.txt | grep -v "^ *$" | wc -l` -gt 0 ]
then
	cat ssh-result.txt | grep -v "^ *$"                                                          >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "SSH 설정파일: 설정 파일을 찾을 수 없습니다."                                           >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

# 서비스 포트 점검
echo "③ 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f port1-search.txt ]
then
	if [ `netstat -na | grep "*.$port1 " | grep -i "LISTEN" | head -1 | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
	else
		netstat -na | grep "*.$port1 " | grep -i "LISTEN" | head -1                                >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Enabled"
	fi
else
	if [ `netstat -na | grep "*.22 " | grep -i "LISTEN" | head -1 | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
	else
		netstat -na | grep "*.22 " | grep -i "LISTEN" | head -1                                    >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Enabled"
	fi
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0324 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf port1-search.txt
rm -rf ssh-result.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0325 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                  ftp 서비스 확인                ###################"
echo "###################                 3.25 ftp 서비스 확인                ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1) ProFTP와 VsFTP 설정파일에 포트가 설정된 경우 설정파일에 등록된 포트가 적용됨." >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2) 설정파일에 포트가 설정되지 않은 경우 /etc/services 파일에 등록된 포트가 적용됨." >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(2)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(2)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(3)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(3)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -na | grep "*.21 " | grep -i "LISTEN" | head -1                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
fi
################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
	flag1="Enabled"
else
	echo "☞ FTP Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0325 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0326 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                ftp 계정 shell 제한              ###################"
echo "###################               3.26 ftp 계정 shell 제한              ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "■     : ftp 서비스 사용 시 ftp 계정에 /bin/false 쉘을 부여하면 양호"  				   >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(2)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(2)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(3)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(3)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -na | grep "*.21 " | grep -i "LISTEN" | head -1                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
fi
################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
	flag1="Enabled"

	echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo "③ ftp 계정 쉘 확인"                                                                     >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
	if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
	then
		cat /etc/passwd | awk -F: '$1=="ftp"'                                                        >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat /etc/passwd | awk -F: '$1=="ftp"' | egrep -i "nologin|false" | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	else
		echo "ftp 계정이 존재하지 않음.(양호)"                                                       >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l | sed -e 's/^ *//g' -e 's/ *$//g'`
	fi

else
	echo "☞ FTP Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo Result=$flag1":"$flag2                                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0326 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0327 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################         Ftpusers 파일 소유자 및 권한 설정       ###################"
echo "###################        3.27 Ftpusers 파일 소유자 및 권한 설정       ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 이하이면 양호"                     >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(2)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(2)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(3)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(3)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -na | grep "*.21 " | grep -i "LISTEN" | head -1                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
fi
################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
	flag1="Enabled"

	echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo "③ ftpusers 파일 소유자 및 권한 확인"                                                    >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                       > ftpusers.txt
	ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
	for file in $ServiceDIR
	do
		if [ -f $file ]
		then
			ls -alL $file                                                                              >> ftpusers.txt
		fi
	done
	if [ `cat ftpusers.txt | wc -l` -gt 1 ]
	then
		cat ftpusers.txt | grep -v "^ *$"                                                            >> $HOSTNAME.sol.result.txt 2>&1
		
		for file2 in `awk -F" " '{print $9}' ftpusers.txt`
		do
			if [ `perm $file2 | awk -F" " '{ print $1 }'` -gt 640 -o `ls -l $file2 | awk -F" " '{print $3}'` != "root" ]
			then
				flag2="F"
				break
			else
				flag2="O"
			fi
		done
		
	else
		echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $HOSTNAME.sol.result.txt 2>&1
		flag2="F"
	fi
	
else
	echo "☞ FTP Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0327 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf ftpusers.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0328 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################                 Ftpusers 파일 설정              ###################"
echo "###################                3.28 Ftpusers 파일 설정              ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: ftp를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호"         >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2-1)proftpd: proftpd.conf 파일에 RootLogin 로그인 설정이 없거나, off 이면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2-2)proftpd: RootLogin 설정이 on 이면 /etc/ftpusers 또는 /etc/ftpd/ftpusers 파일에 root계정이 등록되어 있으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(2)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(2)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "(3)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "(3)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -na | grep "*.21 " | grep -i "LISTEN" | head -1                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
fi
################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
	flag1="Enabled"
	
	echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo "③ ftpusers 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
	echo " "                                                                                       > ftpusers.txt
	if [ -f proftp-profile.txt ]
	then
		if [ `cat $profile | grep -i "RootLogin" | grep -v "^#" | wc -l` -gt 0 ]
		then
			echo "● ProFTP 설정파일: `cat $profile | grep -i "RootLogin" | grep -v "^#"`"              >> $HOSTNAME.sol.result.txt 2>&1
		else
			echo "● ProFTP 설정파일: RootLogin 설정 없음.(Default off)"                                >> $HOSTNAME.sol.result.txt 2>&1
		fi
	fi
	ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
	for file in $ServiceDIR
	do
		if [ -f $file ]
		then
			if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]
			then
				echo "● $file 파일내용: `cat $file | grep "root" | grep -v "^#"` 계정이 등록되어 있음."  >> ftpusers.txt
				echo "check"                                                                             > check.txt
				flag2=`cat $file | grep "root" | grep -v "^#"`
			else
				echo "● $file 파일내용: root 계정이 등록되어 있지 않음."                                 >> ftpusers.txt
				echo "check"                                                                             > check.txt
				flag2="F"
			fi
		fi
	done
	
	if [ -f check.txt ]
	then
		cat ftpusers.txt | grep -v "^ *$"                                                            >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $HOSTNAME.sol.result.txt 2>&1
		flag2="F"
	fi
else
	echo "☞ FTP Service Disable"                                                                >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0328 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
rm -rf ftpusers.txt
rm -rf check.txt
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0329 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             at 파일 소유자 및 권한설정          ###################"
echo "###################            3.29 at 파일 소유자 및 권한설정          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: at.allow 또는 at.deny 파일 권한이 640 이하이고 소유자가 root일 경우 양호"        >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① at.allow 파일 권한 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/cron.d/at.allow ]
then
	ls -alL /etc/cron.d/at.allow                                                                 >> $HOSTNAME.sol.result.txt 2>&1
	flag1=`perm /etc/cron.d/at.allow | awk -F" " '{print $3 ":" $1 }'`
else
	echo "/etc/cron.d/at.allow 파일이 없습니다."                                                 >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Null:Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② at.deny 파일 권한 확인"                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/cron.d/at.deny ]
then
	ls -alL /etc/cron.d/at.deny                                                                  >> $HOSTNAME.sol.result.txt 2>&1
	flag2=`perm /etc/cron.d/at.deny | awk -F" " '{print $3 ":" $1 }'`
else
	echo "/etc/cron.d/at.deny 파일이 없습니다."                                                  >> $HOSTNAME.sol.result.txt 2>&1
	flag2="Null:Null"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0329 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0330 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################               SNMP 서비스 구동 점검             ###################"
echo "###################              3.30 SNMP 서비스 구동 점검             ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"                           >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ `netstat -na | grep "*.161 " | grep -i "idle" | wc -l` -eq 0 ]
then
	echo "☞ SNMP Service Disable"                                                               >> $HOSTNAME.sol.result.txt 2>&1
	flag="Disabled"
else
	flag="Enabled"
	echo "☞ SNMP 서비스 활성화 여부 확인(UDP 161)"                                              >> $HOSTNAME.sol.result.txt 2>&1
  echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	netstat -na | grep "*.161 " | grep -i "idle"                                                 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0330 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0331 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################      snmp 서비스 커뮤티니스트링의 복잡성 설정   ###################"
echo "###################     3.31 snmp 서비스 커뮤티니스트링의 복잡성 설정   ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"                         >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (1) Solaris 9 이하 버전을 사용할 경우: /etc/snmp/conf/snmpd.conf 파일 설정 확인" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (2) Solaris 10 이상 버전을 사용할 경우: /etc/sma/snmp/snmpd.conf 파일 설정 확인" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① SNMP 서비스 활성화 여부 확인(UDP 161)"                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `netstat -na | grep "*.161 " | grep -i "idle" | wc -l` -eq 0 ]
then
	echo "☞ SNMP Service Disable"                                                               >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
else
	netstat -na | grep "*.161 " | grep -i "idle"                                                 >> $HOSTNAME.sol.result.txt 2>&1
	flag1="M/T"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② SNMP Community String 설정 값"                                                        >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo "● SNMP 버전 확인: `uname -a`"                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "● SNMP Community 확인(Solaris 9 버전 이하)"                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------"                                  >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/snmp/conf/snmpd.conf ]
then
	cat /etc/snmp/conf/snmpd.conf | egrep -i "read-community" | egrep -v "^#" | grep -v "group"  >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "/etc/snmp/conf/snmpd.conf 파일이 없습니다."                                            >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "● SNMP Community 확인(Solaris 10 버전 이상)"                                             >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------"                                  >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/sma/snmp/snmpd.conf ]
then
	cat /etc/sma/snmp/snmpd.conf | egrep -i "rocommunity" | egrep -v "^#"                        >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "/etc/sma/snmp/snmpd.conf 파일이 없습니다."                                             >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0331 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0332 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             로그온 시 경고 메시지 제공          ###################"
echo "###################            3.32 로그온 시 경고 메시지 제공          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: /etc/motd와 /etc/issue 파일에 로그온 경고 메시지가 설정되어 있고,"                            >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : Telnet 서비스를 사용하지 않거나, 사용시 Telnet 서비스 배너가 설정되어 있으면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/motd 파일 설정"                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/motd ]
then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/motd | grep -v "^ *$"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다."                                             >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/motd 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② /etc/issue 파일 설정"                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/issue ]
then
	if [ `cat /etc/issue | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/issue | grep -v "^ *$"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다."                                             >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/issue 파일이 없습니다."                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "③ Telnet 서비스 배너 설정 확인"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "● /etc/services 파일에서 포트 확인:"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "-------------------------------------------------------------"                           >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "● 서비스 포트 활성화 여부 확인:"                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo "-------------------------------------------------------------"                           >> $HOSTNAME.sol.result.txt 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                                 >> $HOSTNAME.sol.result.txt 2>&1
		flag1="M/T"
	else
		echo "☞ Telnet Service Disable"                                                           >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
	fi
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "● /etc/default/telnetd 파일 설정:"                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "-------------------------------------------------------------"                           >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/default/telnetd ]
then
	if [ `cat /etc/default/telnetd | grep -i "banner" | grep -v "^#" | wc -l` -gt 0 ]
	then
		cat /etc/default/telnetd | grep -i "banner" | grep -v "^#"                                 >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "BANNER 설정내용이 없습니다.(취약)"                                                   >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/default/telnetd 파일이 없습니다.(취약)"                                           >> $HOSTNAME.sol.result.txt 2>&1
fi

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[SSH] /etc/ssh/sshd_config 파일 확인 "                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "--------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/ssh/sshd_config | egrep -i 'Banner' 										>> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1                                                                                      >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0332 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0333 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################              NFS 설정 파일 접근 권한            ###################"
echo "###################             3.33 NFS 설정 파일 접근 권한            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: NFS 서버 데몬이 동작하지 않거나, /etc/dfs/dfstab 파일의 권한이 644 이하이고 소유자가 root이면 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : (/etc/dfs/dfstab 파일 없으면 NFS서비스 이용이 불가능함으로 양호)"              >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $HOSTNAME.sol.result.txt 2>&1
   flag1="Enabled"
 else
   echo "☞ NFS Service Disable"                                                               >> $HOSTNAME.sol.result.txt 2>&1
   flag1="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② /etc/dfs/dfstab 파일 권한 설정"                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/dfs/dfstab ]
  then
   ls -alL /etc/dfs/dfstab                                                                     >> $HOSTNAME.sol.result.txt 2>&1
   flag2=`perm /etc/dfs/dfstab | awk -F" " '{print $3 ":" $1 }'`
  else
   echo "/etc/dfs/dfstab 파일이 없습니다.(양호)"                                               >> $HOSTNAME.sol.result.txt 2>&1
   flag1="Disabled"
   flag2="Disabled:Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0333 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1






echo "0334 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################               expn, vrfy 명령어 제한            ###################"
echo "###################              3.34 expn, vrfy 명령어 제한            ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"     >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② 서비스 활성화 여부 확인"                                                        	   >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `uname -r | grep "5.9" | wc -l` -gt 0 ]
then
	if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
	then
		port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
		if [ `netstat -na | grep "*.$port " | grep -i "LISTEN" | wc -l` -gt 0 ]
		then
			echo "netstat -na | grep *.25 : "							   						>> $HOSTNAME.sol.result.txt 2>&1
			netstat -na | grep "*.$port " | grep -i "LISTEN" | head -1                          >> $HOSTNAME.sol.result.txt 2>&1
			echo "ps -ef | grep sendmail : "							     					>> $HOSTNAME.sol.result.txt 2>&1		
			ps -ef | grep sendmail									     						>> $HOSTNAME.sol.result.txt 2>&1
			echo " "                                                                            > sendmail.txt
		fi
	fi
	if [ -f sendmail.txt ]
	then
		rm -rf sendmail.txt
		flag1="Enabled"
	else
		echo "☞ Sendmail Service Disable"                                                      >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
		flag2="Disabled"
	fi		
else
	if [ `svcs sendmail | grep -i "^online" | wc -l` -gt 0 ]
	then
		echo "svcs sendmail : "					                                 				>> $HOSTNAME.sol.result.txt 2>&1		
		svcs sendmail | grep -i "^online"			                                 			>> $HOSTNAME.sol.result.txt 2>&1
		echo "ps -ef | grep sendmail : "							    				 		>> $HOSTNAME.sol.result.txt 2>&1		
		ps -ef | grep sendmail									     							>> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                > sendmail.txt
	fi
	if [ -f sendmail.txt ]
	then
		rm -rf sendmail.txt
		flag1="Enabled"
	else
		echo "☞ Sendmail Service Disable"                                                     >> $HOSTNAME.sol.result.txt 2>&1
		flag1="Disabled"
		flag2="Disabled"
	fi	
fi

if [ $flag1 = "Enabled" ]
then

	echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"                                               >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
	    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                                 >> $HOSTNAME.sol.result.txt 2>&1
	    
	    if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep noexpn | wc -l` -eq 0 ]
		    then
					flag2="F"    
		    else
		    	if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep novrfy | wc -l` -eq 0 ]
		    	then
		    		flag2="F"
		    	else
		    		flag2="O"
		    	fi
		    fi
		    
	  else
	    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                              >> $HOSTNAME.sol.result.txt 2>&1
	    flag2="Null"
	fi
else
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0334 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0335 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#####################          Apache 웹서비스 정보 숨김           ####################"
echo "#####################         3.35 Apache 웹서비스 정보 숨김           ####################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: ServerTokens 지시자로 헤더에 전송되는 정보를 설정할 수 있음.(ServerTokens Prod 설정인 경우 양호)" >> $HOSTNAME.sol.result.txt 2>&1
echo "■       : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨."  >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ ! $apaflag -eq 0 ]
then
	flag1="Enabled"
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $HOSTNAME.sol.result.txt 2>&1
	echo "------------------------------------------------------------------------------"        >> $HOSTNAME.sol.result.txt 2>&1
	if [ `cat $ACONF | grep -i "ServerTokens" | grep -v '\#' | wc -l` -gt 0 ]
	then
		cat $ACONF | grep -i "ServerTokens" | grep -v '\#'                                         >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		flag2=`cat $ACONF | grep -i "ServerTokens" | grep -v '\#' | awk -F" " '{print $2}'`
	else
		echo "ServerTokens 지시자가 설정되어 있지 않습니다.(취약)"                                 >> $HOSTNAME.sol.result.txt 2>&1
		echo " "                                                                                   >> $HOSTNAME.sol.result.txt 2>&1
		flag2="Null"
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
	flag1="Disabled"
	flag2="Disabled"
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result=$flag1":"$flag2                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0335 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##############################     4. 패치 관리      ##################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0401 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################        최신 보안패치 및 벤더 권고사항 적용      ###################"
echo "###################       4.01 최신 보안패치 및 벤더 권고사항 적용      ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"             >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ uname -a 확인"    		                                                       		       >> $HOSTNAME.sol.result.txt 2>&1
uname -a																		   			                                           >> $HOSTNAME.sol.result.txt 2>&1

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0401 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "##############################     5. 로그 관리      ##################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0501 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################             로그의 정기적 검토 및 보고          ###################"
echo "###################            5.01 로그의 정기적 검토 및 보고          ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고가 이루어지고 있는 경우 양호" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 담당자 인터뷰 및 증적확인"                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
echo "① 일정 주기로 로그를 점검하고 있는가?"                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "② 로그 점검결과에 따른 결과보고서가 존재하는가?"                                        >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0501 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1



echo "0502 START"                                                                              >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "###################            정책에 따른 시스템 로깅 설정         ###################"
echo "###################           5.02 정책에 따른 시스템 로깅 설정         ###################" >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 기준: syslog 에 중요 로그 정보에 대한 설정이 되어 있을 경우 양호"                      >> $HOSTNAME.sol.result.txt 2>&1
echo "■ 현황"                                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "① SYSLOG 데몬 동작 확인"                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ `ps -ef | grep 'syslog' | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "☞ SYSLOG Service Disable"                                                             >> $HOSTNAME.sol.result.txt 2>&1
else
	ps -ef | grep 'syslog' | grep -v 'grep'                                                      >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "② SYSLOG 설정 확인"                                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/syslog.conf ]
then
	if [ `cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $HOSTNAME.sol.result.txt 2>&1
	else
		echo "/etc/syslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"                      >> $HOSTNAME.sol.result.txt 2>&1
	fi
else
	echo "/etc/syslog.conf 파일이 없습니다."                                                     >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
	echo Result="M/T"                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "0502 END"                                                                                >> $HOSTNAME.sol.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.sol.result.txt 2>&1
echo "=======================================================================================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
rm -rf proftpd.txt
rm -rf vsftpd.txt
echo "***************************************** END *****************************************" >> $HOSTNAME.sol.result.txt 2>&1
date                                                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo "***************************************** END *****************************************"
echo "END_RESULT"                                                                              >> $HOSTNAME.sol.result.txt 2>&1


echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"

echo "@@FINISH"                                                                                >> $HOSTNAME.sol.result.txt 2>&1


echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "=========================== System Information Query Start ============================"
echo "=========================== System Information Query Start ============================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "################################ Kernel Information  ##################################"
echo "################################ Kernel Information  ##################################" >> $HOSTNAME.sol.result.txt 2>&1
uname -a                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "################################## IP Information #####################################"
echo "################################## IP Information #####################################" >> $HOSTNAME.sol.result.txt 2>&1
ifconfig -a                                                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#################################  Network Status   ###################################"
echo "#################################  Network Status   ###################################" >> $HOSTNAME.sol.result.txt 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED"                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "##############################  Routing Information   #################################"
echo "##############################  Routing Information   #################################" >> $HOSTNAME.sol.result.txt 2>&1
netstat -rn                                                                                    >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "#################################  Process Status   ###################################"
echo "#################################  Process Status   ###################################" >> $HOSTNAME.sol.result.txt 2>&1
ps -ef                                                                                         >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "####################################  User Env   ######################################"
echo "####################################  User Env   ######################################" >> $HOSTNAME.sol.result.txt 2>&1
env                                                                                            >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "=========================== System Information Query End =============================="
echo "=========================== System Information Query End ==============================" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "*************************************** START *****************************************"
echo "*************************************** START *****************************************" >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1





echo "■ /etc/passwd 파일"                                                                      >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/passwd ]
then
  cat /etc/passwd                                                                              >> $HOSTNAME.sol.result.txt 2>&1
else
	echo "/etc/shadow 파일이 없습니다."                                                          >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "■ /etc/shadow 파일"                                                                      >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
if [ -f /etc/shadow ]
then
  cat /etc/shadow                                                                              >> $HOSTNAME.sol.result.txt 2>&1
else
  echo "/etc/shadow 파일이 없습니다."                                                          >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "■ /etc/group 파일"                                                                  >> $HOSTNAME.sol.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.sol.result.txt 2>&1
cat /etc/group                                                                                 >> $HOSTNAME.sol.result.txt 2>&1

echo " "                                                                                       >> $HOSTNAME.hp.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.hp.result.txt 2>&1
echo "[참고] /etc/ssh/sshd_config 파일 내용"                        														 >> $HOSTNAME.hp.result.txt 2>&1
echo "------------------------------------------------------------------------------"          >> $HOSTNAME.hp.result.txt 2>&1
	cat /etc/ssh/sshd_config                                                              >> $HOSTNAME.hp.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.hp.result.txt 2>&1
echo "#######################################################################################" >> $HOSTNAME.hp.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.hp.result.txt 2>&1


echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고] 사용자 별 profile 내용"                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo ": 사용자 profile 또는 profile 내 TMOUT 설정이 없는 경우 결과 없음 (/etc/profile을 따름)" >> $HOSTNAME.sol.result.txt 2>&1
echo "-----------------------------------------------"                                         >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

awk -F: '{print $1 ":" $6}' /etc/passwd > profilepath.txt

for result in `cat profilepath.txt`
do
	echo $result > tempfile.txt
	var=`awk -F":" '{print $2}' tempfile.txt`

	if [ $var = "/" ]
	then
		if [ `ls -f / | grep "^\.profile$" | wc -l` -gt 0 ]
		then
			filename=`ls -f / | grep "^\.profile$"`

			if [ `grep -i TMOUT /$filename | grep -v "^#" | wc -l` -gt 0 ]
			then
				awk -F":" '{print $1}' tempfile.txt                                                    >> $HOSTNAME.sol.result.txt 2>&1
				echo "-----------------------------------------------"                                 >> $HOSTNAME.sol.result.txt 2>&1
				grep -i TMOUT /$filename | grep -v "^#"	                                               >> $HOSTNAME.sol.result.txt 2>&1
				echo " "                                                                               >> $HOSTNAME.sol.result.txt 2>&1
# 사용자 profile이 존재하는 경우만 출력하기 위해 주석 처리
#			else
#				awk -F":" '{print $1}' tempfile.txt                                                    >> $HOSTNAME.sol.result.txt 2>&1
#                         	echo "----------------------------------------"                      >> $HOSTNAME.sol.result.txt 2>&1
#                         	echo $filename"에 TMOUT 설정이 존재하지 않음"                        >> $HOSTNAME.sol.result.txt 2>&1
#				echo " "                                                                               >> $HOSTNAME.sol.result.txt 2>&1
			fi
#		else
#                        awk -F":" '{print $1}' tempfile.txt                                    >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "----------------------------------------"                        >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "사용자 profile 파일이 존재하지 않음"                             >> $HOSTNAME.sol.result.txt 2>&1
#			echo " "                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		pathname=`awk -F":" '{print $2}' tempfile.txt`
					if [ -f $pathname ]
					then
                if [ `ls -f $pathname | grep "^\.profile$" | wc -l` -gt 0 ]
                then
                        filename = `ls -f $pathname | grep "^\.profile$"`

                        if [ `grep -i TMOUT $pathname/$filename | grep -v "^#" | wc -l` -gt 0 ]
                        then
                                awk -F":" '{print $1}' tempfile.txt                            >> $HOSTNAME.sol.result.txt 2>&1
                                echo "----------------------------------------"                >> $HOSTNAME.sol.result.txt 2>&1
                                grep -i TMOUT $pathname/$filename | grep -v "^#"               >> $HOSTNAME.sol.result.txt 2>&1
                                echo " "                                                       >> $HOSTNAME.sol.result.txt 2>&1
# 사용자 profile이 존재하는 경우만 출력하기 위해 주석 처리
#                        else
#                                awk -F":" '{print $1}' tempfile.txt                            >> $HOSTNAME.sol.result.txt 2>&1
#                                echo "----------------------------------------"                >> $HOSTNAME.sol.result.txt 2>&1
#                                echo $filename"에 TMOUT 설정이 존재하지 않음"                  >> $HOSTNAME.sol.result.txt 2>&1
#                                echo " "                                                       >> $HOSTNAME.sol.result.txt 2>&1
                        fi
#                else
#                        awk -F":" '{print $1}' tempfile.txt                                    >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "----------------------------------------"                        >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "사용자 profile 파일이 존재하지 않음"                             >> $HOSTNAME.sol.result.txt 2>&1
#                        echo " "                                                               >> $HOSTNAME.sol.result.txt 2>&1
								 fi
					fi			 
	fi
done




echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고] 소유자가 존재하지 않는 파일 전체 목록"                                        >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
		cat 1.17.txt                                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고] SUID,SGID,Sticky bit 설정 파일 전체 목록"                                     >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
    cat 1.24.txt                                                                               >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고] World Writable 파일 전체 목록"                                                >> $HOSTNAME.sol.result.txt 2>&1
		echo "------------------------------------------------------------------------------"      >> $HOSTNAME.sol.result.txt 2>&1
    cat world-writable.txt                                                                     >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "[참고] 사용자 별 profile 내용"                                                           >> $HOSTNAME.sol.result.txt 2>&1
echo ": 사용자 profile 또는 profile 내 UMASK 설정이 없는 경우 결과 없음 (/etc/profile을 따름)" >> $HOSTNAME.sol.result.txt 2>&1
echo "-----------------------------------------------"                                         >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1

for result in `cat profilepath.txt`
do
	echo $result > tempfile.txt
	var=`awk -F":" '{print $2}' tempfile.txt`

	if [ $var = "/" ]
	then
		if [ `ls -f / | grep "^\.profile$" | wc -l` -gt 0 ]
		then
			filename=`ls -f / | grep "^\.profile$"`

			if [ `grep -i umask /$filename | grep -v "^#" | wc -l` -gt 0 ]
			then
				awk -F":" '{print $1}' tempfile.txt                                                    >> $HOSTNAME.sol.result.txt 2>&1
				echo "-----------------------------------------------"                                 >> $HOSTNAME.sol.result.txt 2>&1
				grep -A 1 -B 1 -i umask /$filename | grep -v "^#"	                                     >> $HOSTNAME.sol.result.txt 2>&1
				echo " "                                                                               >> $HOSTNAME.sol.result.txt 2>&1
# 사용자 profile이 존재하는 경우만 출력하기 위해 주석 처리
#			else
#				awk -F":" '{print $1}' tempfile.txt                                                    >> $HOSTNAME.sol.result.txt 2>&1
#                         	echo "----------------------------------------"                    >> $HOSTNAME.sol.result.txt 2>&1
#                         	echo $filename"에 UMASK 설정이 존재하지 않음"                      >> $HOSTNAME.sol.result.txt 2>&1
#				echo " "                                                                               >> $HOSTNAME.sol.result.txt 2>&1
			fi
#		else
#                        awk -F":" '{print $1}' tempfile.txt                                   >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "----------------------------------------"                       >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "사용자 profile 파일이 존재하지 않음"                            >> $HOSTNAME.sol.result.txt 2>&1
#			echo " "                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
		fi
	else
		pathname=`awk -F":" '{print $2}' tempfile.txt`
					if [ -f $pathname ]
					then
                if [ `ls -f $pathname | grep "^\.profile$" | wc -l` -gt 0 ]
                then
                        filename = `ls -f $pathname | grep "^\.profile$"`

                        if [ `grep -i umask $pathname/$filename | grep -v "^#" | wc -l` -gt 0 ]
                        then
                                awk -F":" '{print $1}' tempfile.txt                            >> $HOSTNAME.sol.result.txt 2>&1
                                echo "----------------------------------------"                >> $HOSTNAME.sol.result.txt 2>&1
                                grep -A 1 -B 1 -i umask $pathname/$filename | grep -v "^#"     >> $HOSTNAME.sol.result.txt 2>&1
                                echo " "                                                       >> $HOSTNAME.sol.result.txt 2>&1
# 사용자 profile이 존재하는 경우만 출력하기 위해 주석 처리
#                        else
#                                awk -F":" '{print $1}' tempfile.txt                           >> $HOSTNAME.sol.result.txt 2>&1
#                                echo "----------------------------------------"               >> $HOSTNAME.sol.result.txt 2>&1
#                                echo $filename"에 UMASK 설정이 존재하지 않음"                 >> $HOSTNAME.sol.result.txt 2>&1
#                                echo " "                                                      >> $HOSTNAME.sol.result.txt 2>&1
                        fi
#                else
#                        awk -F":" '{print $1}' tempfile.txt                                   >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "----------------------------------------"                       >> $HOSTNAME.sol.result.txt 2>&1
#                        echo "사용자 profile 파일이 존재하지 않음"                            >> $HOSTNAME.sol.result.txt 2>&1
#                        echo " "                                                              >> $HOSTNAME.sol.result.txt 2>&1
								 fi
					fi			 
	fi
done

rm -rf tempfile.txt
rm -rf profilepath.txt

echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo "☞ 설치된 패치 확인"		                                                       		       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
if [ `uname -r | grep "5.11" | wc -l` -gt 0 ]
	then
		pkg list -uv		                                                             	             >> $HOSTNAME.sol.result.txt 2>&1
	else
		showrev -p                                                                                 >> $HOSTNAME.sol.result.txt 2>&1
fi
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1
echo " "                                                                                       >> $HOSTNAME.sol.result.txt 2>&1


rm -rf 1.17.txt
rm -rf 1.24.txt
rm -rf world-writable.txt
