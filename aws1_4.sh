#!/bin/bash 
set -x && PS4='$(date "+%Y-%m-%d %H:%M:%S") '

region=('eu-north-1' 'ap-south-1' 'eu-west-3' 'eu-west-2' 'eu-west-1' 'ap-northeast-3' 'ap-northeast-2' 'ap-northeast-1' 'sa-east-1' 'ca-central-1' 'ap-southeast-1' 'ap-southeast-2' 'eu-central-1' 'us-east-1' 'us-east-2' 'us-west-1' 'us-west-2')

#region=('ap-northeast-1')
#region=()
rootpath="./14mar_prd"
customeraccount = "289537550737"
mkdir -p $rootpath



1_4() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} rootアカウントのアクセスキーが設定されていないこと AccountAccessKeysPresent" > $file_name
	#echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,9,14 | grep -B1 '<root_account>'" >> $file_name 
	#aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,9,14 | grep -B1 '<root_account>'  >> $file_name   
	
	echo ">> aws iam get-account-summary" >> $file_name 
	aws iam get-account-summary  >> $file_name   
	
}


1_5() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} rootアカウントがMFAにより保護されていること AccountMFAEnabled" > $file_name
	echo ">> aws iam get-account-summary" >> $file_name 
	aws iam get-account-summary  >> $file_name   
}


1_6() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} rootアカウントがハードウェアMFAにより保護されていること AccountMFAEnabled/VirtualMFADevices" > $file_name
echo ">> aws iam get-account-summary" >> $file_name
aws iam get-account-summary >> $file_name

COMMAND113=$(aws iam get-account-summary --output text --query 'SummaryMap.AccountMFAEnabled')

  if [ "$COMMAND113" == "1" ]; then
    COMMAND114=$(aws iam list-virtual-mfa-devices --output text --assignment-status Assigned --query 'VirtualMFADevices[*].[SerialNumber]' | grep "^arn:${AWS_PARTITION}:iam::[0-9]\{12\}:mfa/root-account-mfa-device$")
   
   echo ">> aws iam list-virtual-mfa-devices --assignment-status Assigned"   >> $file_name
   echo "$COMMAND114"   >> $file_name

  fi

echo ">> aws iam list-virtual-mfa-devices" >> $file_name
aws iam list-virtual-mfa-devices >> $file_name

}


1_7() {
echo  `date` ${FUNCNAME[0]}  $1 start 

file_name=$rootpath/${FUNCNAME[0]}_$1.txt
file_name_credential=$rootpath/${FUNCNAME[0]}_credential_report_$1.txt
echo "${FUNCNAME[0]} rootアカウントが利用されていないこと" > $file_name
	aws iam generate-credential-report

	echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d" > $file_name_credential
	aws iam get-credential-report --query 'Content' --output text | base64 -d >> $file_name_credential
	echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>'" >> $file_name
	aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>' >> $file_name
}



1_8_9() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} パスワードポリシー" > $file_name
echo ">> aws iam get-account-password-policy" >> $file_name
	aws iam get-account-password-policy >> $file_name   
}


1_10() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} コンソールログイン用のパスワードが設定されたIAMユーザにMFAが有効化されていること" > $file_name
	echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,8" >> $file_name  
	aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,8 >> $file_name  
}



1_12() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} 45日以上利用されていない認証情報は無効化されていること" > $file_name
	echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16" >> $file_name 
	aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16 >> $file_name  
}


1_14() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} アクセスキーが90日以内にローテーションされていること" > $file_name
	echo ">> aws iam get-credential-report --query 'Content' --output text | base64 -d" >> $file_name 
	aws iam get-credential-report --query 'Content' --output text | base64 -d >> $file_name   
	
}


1_15() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} IAMポリシーがグループまたはロールにのみ適用されていること" > $file_name

echo ">> aws iam list-users --output text" >> $file_name
aws iam list-users --output text >> $file_name

result=$(aws iam list-users --query 'Users[*].UserName' --output text)
echo ">> aws iam list-users --query 'Users[*].UserName' --output text" >> $file_name
echo "$result" >> $file_name

for keyid in $result;
do 
	echo "Found" $keyid
	echo "Found" "KeyId:" $keyid >> $file_name

	echo ">> aws iam list-attached-user-policies --user-name $keyid" >> $file_name
	aws iam list-attached-user-policies --user-name $keyid >> $file_name
	
	echo ">> aws iam list-user-policies --user-name $keyid" >> $file_name 
	aws iam list-user-policies --user-name $keyid >> $file_name 
done
}


1_16() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
file_name_1=$rootpath/${FUNCNAME[0]}_policy_list_result_tmp_$1.txt

touch $file_name $file_name_1 
echo "${FUNCNAME[0]} フルコントロール(全リソースおよび全アクション)権限を持つポリシーが作成されていないこと" > $file_name

echo ">>aws iam list-policies --output text">> $file_name
aws iam list-policies --output text >> $file_name
aws iam list-policies --output text | grep -v "arn:aws:iam::aws:" > $file_name_1

sed -i '/^$/d' $file_name_1  

while read line; 
do
arn=$(echo $line  |tr '\t' ' ' |cut -d' ' -f2)
version=$(echo $line  |tr '\t' ' ' |cut -d' ' -f5)
arnlength=${#line}
if [ $arnlength -ge 0 ]; then
echo $arn $version >> $file_name
echo ">> aws iam get-policy-version --policy-arn $arn --version-id $version" >> $file_name
aws iam get-policy-version --policy-arn $arn --version-id $version >> $file_name
fi
done < $file_name_1  

}


1_17() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} AWSサポートでインシデントを管理するためのサポートロールが作成されていること AWSSupportAccess/AttachmentCount" > $file_name
	echo ">> aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"">> $file_name
	aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"  >> $file_name   
	
	echo ">> aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess">> $file_name
	aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess  >> $file_name 
}

1_19() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} AWS IAMに保存されている期限切れのSSL/TLS証明書がすべて削除されていること" > $file_name
	echo ">> aws iam list-server-certificates">> $file_name
	aws iam list-server-certificates  >> $file_name   
}



1_20() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_all_$1.txt
touch  $file_name
echo "${FUNCNAME[0]} IAM Access analyzerが有効になっていることを確認します。 $1" > $file_name

echo ">>  aws accessanalyzer list-analyzers --region $1" >> $file_name
aws accessanalyzer list-analyzers --region $1 >> $file_name
}



2_1_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
echo "${FUNCNAME[0]} S3バケットでデフォルトの暗号化（SSE）が有効になっており、それを強制するポリシーが設定されているか $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws s3 ls --output text | awk '{print $3}')
    echo ">> aws s3 ls --output text | awk '{print $3}'" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 
    if [[ $LIST_OF_S3_INSTANCES ]];then
      for s3 in $LIST_OF_S3_INSTANCES; do
        IS_ENCRYPTED=$(aws s3api get-bucket-encryption --bucket $s3 )
		echo ">> aws s3api get-bucket-encryption --bucket $s3" >> $file_name
		echo "$IS_ENCRYPTED" >> $file_name
       
      done
  
    fi
	
}



2_1_2() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
echo "${FUNCNAME[0]} S3バケットポリシーがHTTPSリクエストを許可していること $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws s3 ls --output text | awk '{print $3}')
    echo ">> aws s3 ls --output text | awk '{print $3}'" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 
    if [[ $LIST_OF_S3_INSTANCES ]];then
      for s3 in $LIST_OF_S3_INSTANCES; do
        
		echo ">> aws s3api get-bucket-policy --bucket $s3" >> $file_name
		aws s3api get-bucket-policy --bucket $s3 >> $file_name
       
      done
  
    fi
	
}


2_1_3() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
echo "${FUNCNAME[0]} Ensure MFA Delete is enable on S3 buckets $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws s3 ls --output text | awk '{print $3}')
    echo ">> aws s3 ls --output text | awk '{print $3}'" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 
    if [[ $LIST_OF_S3_INSTANCES ]];then
      for s3 in $LIST_OF_S3_INSTANCES; do
       
		echo ">> aws s3api get-bucket-versioning --bucket $s3" >> $file_name
		aws s3api get-bucket-versioning --bucket $s3 >> $file_name
       
      done
  
    fi
	
}


2_1_5() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
file_name2=$rootpath/${FUNCNAME[0]}_$1_account.txt
touch $file_name 
touch $file_name2
echo "${FUNCNAME[0]} Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws s3 ls --output text | awk '{print $3}')
    echo ">> aws s3 ls --output text | awk '{print $3}'" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 
    if [[ $LIST_OF_S3_INSTANCES ]];then
      for s3 in $LIST_OF_S3_INSTANCES; do
        IS_ENCRYPTED=$(aws s3api get-public-access-block --bucket $s3 )
		echo ">> aws s3api get-public-access-block --bucket $s3" >> $file_name
		echo "$IS_ENCRYPTED" >> $file_name
       
      done
  
    fi
	
	echo ">> aws s3control get-public-access-block --account-id  $customeraccount" --region $1 >> $file_name2
	aws s3control get-public-access-block --account-id $customeraccount --region $1 >> $file_name2
	
}

2_2_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_all_$1.txt
touch  $file_name
echo "${FUNCNAME[0]} EBSボリュームが暗号化されていること $1" > $file_name

echo ">> aws ec2 get-ebs-encryption-by-default --region $1" >> $file_name
aws ec2 get-ebs-encryption-by-default --region $1 >> $file_name
}



2_3_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt

touch $file_name 

echo "${FUNCNAME[0]} RDSインスタンスストレージが暗号化されているか $1" > $file_name
	LIST_OF_RDS_INSTANCES=$(aws rds describe-db-instances --region $1 --query 'DBInstances[*].DBInstanceIdentifier')
	
    echo ">> aws rds describe-db-instances --region $1 --query 'DBInstances[*].DBInstanceIdentifier'" >> $file_name
	echo "$LIST_OF_RDS_INSTANCES"  >> $file_name
 	
	 if [[ $LIST_OF_RDS_INSTANCES ]];then
      for rds in $LIST_OF_RDS_INSTANCES; do
        IS_ENCRYPTED=$(aws rds describe-db-instances --region $1 --db-instance-identifier $rds --query 'DBInstances[*].StorageEncrypted' )
		echo ">> aws rds describe-db-instances --region $1 --db-instance-identifier $rds --query 'DBInstances[*].StorageEncrypted'" >> $file_name
		echo "$IS_ENCRYPTED" >> $file_name
       
      done
  
    fi
	
}


3_1() {

#aws cloudtrail get-trail-status --name trail_NHKacademy_Newuni_Kensyo
#aws cloudtrail get-event-selectors --trail-name

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} 全てのリージョンでCloudTrailが有効になっていることS3BucketName/IsMultiRegionTrail/TrailARN $1" > $file_name
echo ">> aws cloudtrail describe-trails --region $1" >> $file_name  
aws cloudtrail describe-trails --region $1 >> $file_name  

}

3_2() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} CloudTrailログ検証が有効になっていることTrailARN $1" > $file_name
 echo ">> aws cloudtrail describe-trails --region $1" >> $file_name
 aws cloudtrail describe-trails --region $1 >> $file_name

}

3_3() {

	echo  `date` ${FUNCNAME[0]} $1 start 
	file_name=$rootpath/${FUNCNAME[0]}_$1.txt
	touch $file_name
	echo -n > $file_name
	echo "${FUNCNAME[0]} S3バケットCloudTrailログがPublicに公開されていないこと" > $file_name

	TRAILS_AND_REGIONS=$(aws cloudtrail describe-trails --region $1 --query 'trailList[*].{Name:TrailARN, HomeRegion:HomeRegion}' --output text 2>&1 | tr "	" ',')
	reg_trail_region=$(echo $TRAILS_AND_REGIONS | cut -d',' -f1)	
	trail=$(echo $TRAILS_AND_REGIONS | cut -d',' -f2)
	trail_count=$((trail_count + 1))

    CLOUDTRAILBUCKET=$(aws cloudtrail describe-trails --region $reg_trail_region --query 'trailList[*].[S3BucketName]' --output text --trail-name-list $trail)
		
	
    if [[ -z $CLOUDTRAILBUCKET ]]; then
          echo "Trail $trail in $reg_trail_region does not publish to S3" >> $file_name
    fi
		
	BUCKET_LOCATION=$(aws s3api get-bucket-location --region $reg_trail_region --bucket $CLOUDTRAILBUCKET --output text 2>&1)
				
		
    if [[ $(echo "$BUCKET_LOCATION" | grep AccessDenied) ]]; then
          echo "Trail $trail in $reg_trail_region Access Denied getting bucket location for $CLOUDTRAILBUCKET"  >> $file_name
          
    fi

	echo ">>aws s3api get-bucket-acl --bucket $CLOUDTRAILBUCKET --region $BUCKET_LOCATION --query 'Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']'" >> $file_name

	aws s3api get-bucket-acl --bucket $CLOUDTRAILBUCKET --region $BUCKET_LOCATION --query 'Grants[?Grantee.URI=="http://acs.amazonaws.com/groups/global/AllUsers"]' >> $file_name
	
}


3_4() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} CloudTrailがCloudWatch Logsと統合されていること CloudWatchLogsLogGroupArn $1" > $file_name

result=$(aws cloudtrail list-trails --region $1 --output text --query 'Trails[].Name')

echo ">>aws cloudtrail list-trails --region $1 --output text --query 'Trails[].Name'" >> $file_name
echo "$result" >> $file_name

for keyid in $result;
do 
#aws cloudtrail get-trail-status --name
	echo ">> aws cloudtrail describe-trails --region $1 --trail-name-list $keyid" >> $file_name
	aws cloudtrail describe-trails --region $1 --trail-name-list $keyid >> $file_name

done

}

3_5() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} 全てのリージョンでAWS Configが有効になっていること  $1" > $file_name
echo ">> aws configservice describe-configuration-recorders --region $1" >> $file_name
aws configservice describe-configuration-recorders --region $1 >> $file_name
echo ">> aws configservice describe-configuration-recorder-status --region $1" >> $file_name
aws configservice describe-configuration-recorder-status --region $1 >> $file_name
}



3_6() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} CloudTrail S3バケットでS3バケットアクセスログが有効になっていること LoggingEnabled/TargetBucket $1" > $file_name

result=$(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --region $1 --output text)
echo "" >> $file_name
echo "$result" >> $file_name

for keyid in $result;
do 

	echo ">> aws s3api get-bucket-logging --bucket $keyid --region $1" >> $file_name 
	aws s3api get-bucket-logging --bucket $keyid --region $1 >> $file_name  

done
}


3_7() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} キーマネジメントシステムのカスタマーマスターキーを使用してCloudTrailログが暗号化されて保存されていること KmsKeyId $1" > $file_name
	echo ">> aws cloudtrail describe-trails --region $1" >> $file_name
	aws cloudtrail describe-trails --region $1 >> $file_name  
}

3_8() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} カスタマーマスターキーのローテーションが有効になっていること KeyRotationEnabled=true $1" > $file_name
result=$(aws kms list-keys --region $1 --query 'Keys[*].KeyId' --output text)
echo ">> aws kms list-keys --region $1 --query 'Keys[*].KeyId' --output text" >> $file_name
echo "$result" >> $file_name

for keyid in $result;
do 
	echo ">> aws kms get-key-rotation-status --key-id $keyid --region $1" >> $file_name  
	aws kms get-key-rotation-status --key-id $keyid --region $1 >> $file_name  
done
}

3_9() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} VPCフローログが全てのVPCで有効になっていること $1" > $file_name

	echo ">> aws ec2 describe-flow-logs --region $1" >> $file_name
	aws ec2 describe-flow-logs --region $1 >> $file_name  
}

3_10() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt

touch $file_name 

echo "${FUNCNAME[0]} Ensure that Object-level logging for write events is enabled for S3 bucket $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws cloudtrail list-trails --region $1 --query Trails[*].Name --output text) 
	
    echo ">> aws cloudtrail list-trails --region $1 --query Trails[*].Name" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 	
	 if [[ $LIST_OF_S3_INSTANCES ]];then
      for s3 in $LIST_OF_S3_INSTANCES; do
        IS_ENCRYPTED=$(aws cloudtrail get-event-selectors --region $1 --trail-name $s3  )
		echo ">> aws cloudtrail get-event-selectors --region $1 --trail-name $s3" >> $file_name
		aws cloudtrail get-event-selectors --region $1 --trail-name $s3 >> $file_name
       
      done
  
    fi
	
}

3_11() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt

touch $file_name 

echo "${FUNCNAME[0]} Ensure that Object-level logging for read events is enabled for S3 bucket (Automated) $1" > $file_name
	LIST_OF_S3_INSTANCES=$(aws cloudtrail list-trails --region $1 --query Trails[*].Name --output text)
	
    echo ">> aws cloudtrail list-trails --region $1 --query Trails[*].Name" >> $file_name
	echo "$LIST_OF_S3_INSTANCES"  >> $file_name
 	
	 if [[ $LIST_OF_S3_INSTANCES ]];then
      for bucket in $LIST_OF_S3_INSTANCES; do
        
		echo ">> aws cloudtrail get-event-selectors --region $1 --trail-name $bucket" >> $file_name
		aws cloudtrail get-event-selectors --region $1 --trail-name $bucket >> $file_name
       
      done
  
    fi
	
}



4_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name

echo "${FUNCNAME[0]} 不正なAPI呼び出しに対してログメトリックフィルタとアラームが存在すること {($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}  $1" > $file_name
result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi


echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
 
}

4_2() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} MFAなしでの管理コンソールサインインに対してログメトリックフィルタとアラームが存在すること {($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}

4_3() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} rootアカウントの使用に対してログメトリックフィルタとアラームが存在すること {$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}


4_4() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} IAMポリシーの変更に対してログメトリックフィルタとアラームが存在すること {($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}



4_5() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} CloudTrail設定の変更に対してログメトリックフィルタとアラームが存在すること {($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}



4_6() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} AWSマネジメントコンソールの認証エラーに対してログメトリックスフィルタとアラームが存在すること {($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}



4_7() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} カスタマーマスターキーの無効化またはスケジュール削除に対してログメトリックフィルタとアラームが存在すること {($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}



4_8() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} S3バケットポリシーの変更に対してログメトリックフィルタとアラームが存在すること {($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}



4_9() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} AWS Config設定の変更に対してログメトリックスフィルタとアラームが存在すること {($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}  $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}



4_10() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} セキュリティグループの変更に対してログメトリックフィルタとアラームが存在すること {($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}

4_11() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} ネットワークアクセスコントロールリスト (NACL) への変更に対するログメトリクスフィルターとアラームが存在すること {($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name
}

4_12() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} ネットワークゲートウェイへの変更に対するログメトリクスフィルターとアラームが存在すること {($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}

4_13() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} ルートテーブルの変更に対してログメトリクスフィルターとアラームが存在すること {($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}

4_14() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} VPC の変更に対してログメトリクスフィルターとアラームが存在すること {($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}

4_15() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} AWS Organizationsの変更に対してログメトリクスフィルタとアラーム通知が設定されていること {($.eventName=AcceptHandshake) || ($.eventName=EnablePolicyType) || ($.eventName=EnableAllFeatures) || ($.eventName=AttachPolicy) || ($.eventName=CancelHandshake) || ($.eventName=CreateAccount) || ($.eventName=CreateOrganization) || ($.eventName=UpdateOrganizationalUnit) || ($.eventName=UpdatePolicy) || ($.eventName=MoveAccount) || ($.eventName=DisablePolicyType) || ($.eventName=RemoveAccountFromOrganization) || ($.eventName=DetachPolicy)} $1" > $file_name

result=$(aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text)
echo ">> aws logs describe-log-groups --region $1 --query 'logGroups[*].logGroupName' --output text" >> $file_name
echo "$result" >> $file_name

if [[ $result ]];then

	for keyid in $result;
	do 
		echo ">> aws logs describe-metric-filters --log-group-name $keyid --region $1" >> $file_name
		aws logs describe-metric-filters --log-group-name $keyid --region $1 >> $file_name
	done
fi

echo ">> aws cloudwatch describe-alarms --region $1" >> $file_name
aws cloudwatch describe-alarms --region $1 >> $file_name

}



5_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} どのセキュリティグループも0.0.0.0/0からポート22への通信を許可していないこと $1" > $file_name

echo ">> aws ec2 describe-security-groups --query ""SecurityGroups[].[GroupName,GroupId]"" --output text --region $1" >> $file_name
aws ec2 describe-security-groups --query ""SecurityGroups[].[GroupName,GroupId]""  --region $1 >> $file_name

echo ">> aws ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=22 --output text --region $1" >> $file_name 
aws ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=22  --region $1 >> $file_name 

echo ">> aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0' --output text --region $1" >> $file_name
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0'  --region $1 >> $file_name

}

5_1_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1_output.txt
file_name2=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
touch $file_name2
echo "${FUNCNAME[0]} Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports $1" > $file_name
	LIST_OF_EC2ACL_INSTANCES=$(aws ec2 describe-network-acls --query 'NetworkAcls[?Entries[?((CidrBlock == `0.0.0.0/0` || Ipv6CidrBlock == `::/0` ) && (Egress == `false`) && (RuleAction == `allow`))]]' --region $1 --output json)
    echo ">> aws ec2 describe-network-acls --query 'NetworkAcls[?Entries[?((CidrBlock == `0.0.0.0/0` || Ipv6CidrBlock == `::/0` ) && (Egress == `false`) && (RuleAction == `allow`))]]' --region $1" >> $file_name
	echo "$LIST_OF_EC2ACL_INSTANCES"  >> $file_name
 	
	echo ">> aws ec2 describe-network-acls --region $1" >> $file_name2
	aws ec2 describe-network-acls --region $1 >> $file_name2
	
}

5_2() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} どのセキュリティグループも0.0.0.0/0からポート3389への通信を許可していないこと $1" > $file_name

echo ">> aws ec2 describe-security-groups --query ""SecurityGroups[].[GroupName,GroupId]"" --output text --region $1" >> $file_name
aws ec2 describe-security-groups --query ""SecurityGroups[].[GroupName,GroupId]""  --region $1 >> $file_name

echo ">> aws ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=3389 --output text --region $1" >> $file_name 
aws ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=3389  --region $1 >> $file_name 

echo ">> aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0' --output text --region $1" >> $file_name
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0'  --region $1 >> $file_name

}


5_2_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1_output.txt
file_name2=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
touch $file_name2
echo "${FUNCNAME[0]} Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports $1" > $file_name
	LIST_OF_EC2ACL_INSTANCES=$(aws ec2 describe-security-group-rules --region $1 --output json --query 'SecurityGroupRules[?(IsEgress==`false` &&(CidrIpv4==`0.0.0.0/0` || CidrIpv6==`::/0`))]' | jq -r '.[] | [.SecurityGroupRuleId, .GroupId, .IpProtocol, .FromPort, .ToPort, .CidrIpv4, .CidrIpv6] | @csv')
    echo ">> aws ec2 describe-security-group-rules --region $1 --output json --query 'SecurityGroupRules[?(IsEgress==`false` &&(CidrIpv4==`0.0.0.0/0` || CidrIpv6==`::/0`))]' | jq -r '.[] | [.SecurityGroupRuleId, .GroupId, .IpProtocol, .FromPort, .ToPort, .CidrIpv4, .CidrIpv6] | @csv'" >> $file_name
	echo "$LIST_OF_EC2ACL_INSTANCES"  >> $file_name
 	
	echo ">> aws ec2 describe-network-acls --region $1" >> $file_name2
	aws ec2 describe-network-acls --region $1 >> $file_name2
	
}


5_3() {

echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} すべてのVPCのデフォルトセキュリティグループがすべてのトラフィックを制限していること $1" > $file_name

echo ">> aws ec2 describe-security-groups --query "SecurityGroups[?GroupName == 'default']" --region $1" >> $file_name
aws ec2 describe-security-groups --query "SecurityGroups[?GroupName == 'default']" --region $1 >> $file_name

}


6_1() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} 管理者権限を持ったユーザがMFAトークンを有効にしていること $1" > $file_name

group_list=$(aws iam list-groups --output text --region $1 --query 'Groups[].GroupName')
for grp in $group_list; do

check_this_group=$(aws iam list-attached-group-policies --region $1 --group-name $grp --output json --query 'AttachedPolicies[].PolicyArn' | grep  "policy/AdministratorAccess")

echo ">> aws iam list-attached-group-policies --region $1 --group-name $grp --output json --query 'AttachedPolicies[].PolicyArn' | grep  'policy/AdministratorAccess'" >> $file_name
echo "$check_this_group" >> $file_name

 if [[ $check_this_group ]]; then
 
 admins=$(aws iam get-group --region $1 --group-name $grp --output json --query 'Users[].UserName' | grep '"' | cut -d'"' -f2 )
 
  for user in $admins; do
	
	echo "MFA check for $user"
	echo "MFA check for $user" >> $file_name
	
	echo ">> aws iam list-mfa-devices --user-name $user" >> $file_name
	aws iam list-mfa-devices --user-name $user >> $file_name
  
  done
 fi
 

done


}



6_2() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} EBSスナップショットがPublicになっていないこと $1" > $file_name

result=$(aws ec2 describe-snapshots --region $1 --owner-ids self --output text --query 'Snapshots[*].{ID:SnapshotId}' --max-items 1000)
echo ">> aws ec2 describe-snapshots --region $1 --owner-ids self --output text --query 'Snapshots[*].{ID:SnapshotId}' --max-items 1000" >> $file_name
echo "$result" >> $file_name

for keyid in $result;
do 
	echo "Found" $keyid
	echo "Found" "KeyId:" $keyid >> $file_name
	echo ">> aws ec2 describe-snapshot-attribute --region $1  --snapshot-id $keyid   --attribute createVolumePermission" >> $file_name 
	aws ec2 describe-snapshot-attribute --region $1  --snapshot-id $keyid   --attribute createVolumePermission >> $file_name  
	
done

}

6_3() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} EC2 AMIがPublicになっていないこと  $1" > $file_name

echo ">> aws ec2 describe-images --owners self --region $1" >> $file_name
aws ec2 describe-images --owners self --region $1 >> $file_name

echo ">> aws ec2 describe-images --owners self --filters ""Name=is-public,Values=true"" --query 'Images[*].{ID:ImageId}' --output text --region $1" >> $file_name
aws ec2 describe-images --owners self --filters ""Name=is-public,Values=true"" --query 'Images[*].{ID:ImageId}' --output text --region $1 >> $file_name

}

6_4() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} GuardDutyが有効になっていること $1" > $file_name

echo ">> aws guardduty list-detectors  --region $1" >> $file_name
aws guardduty list-detectors  --region $1 >> $file_name

}

6_5() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} S3のアクセスログが有効になっているか  $1" > $file_name

LIST_OF_BUCKETS=$(aws s3api list-buckets --query Buckets[*].Name --output text|xargs -n1)

echo ">> aws s3api list-buckets --query Buckets[*].Name --output text|xargs -n1" >> $file_name
echo "$LIST_OF_BUCKETS" >> $file_name

  if [[ $LIST_OF_BUCKETS ]]; then
    for bucket in $LIST_OF_BUCKETS;do
      BUCKET_SERVER_LOG_ENABLED=$(aws s3api get-bucket-logging --bucket $bucket)
	  echo ">> aws s3api get-bucket-logging --bucket $bucket" >> $file_name
	  echo "$BUCKET_SERVER_LOG_ENABLED" >> $file_name 
    done
  fi


}

6_6() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name

echo "${FUNCNAME[0]} Route53ホストゾーンがCloudWatch Logsにクエリを記録しているか $1" > $file_name
  LIST_OF_HOSTED_ZONES=$(aws route53 list-hosted-zones | jq -r ".HostedZones[] | select(.Config.PrivateZone == false) | .Id")
  
  echo ">>aws route53 list-hosted-zones | jq -r '.HostedZones[] | select(.Config.PrivateZone == false) | .Id'" >> $file_name
  echo "$LIST_OF_HOSTED_ZONES" >> $file_name
  
  if [[ $LIST_OF_HOSTED_ZONES ]]; then
    for hostedzoneid in $LIST_OF_HOSTED_ZONES;do
      HOSTED_ZONE_QUERY_LOG_ENABLED=$(aws route53 list-query-logging-configs --hosted-zone-id $hostedzoneid )
      echo ">> aws route53 list-query-logging-configs --hosted-zone-id $hostedzoneid" >> $file_name
	  echo "$HOSTED_ZONE_QUERY_LOG_ENABLED" >> $file_name
    done
  
   
  fi
}


6_7() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt

echo "${FUNCNAME[0]} APIを呼び出すLambda関数がCloudTrailに記録されているか $1" > $file_name

result=$(aws cloudtrail list-trails --region $1 --output text --query 'Trails[].Name')

	echo ">> aws cloudtrail list-trails --region $1 --output text --query 'Trails[].Name'" >> $file_name
	echo "$result" >> $file_name
	
	
for keyid in $result;
do 
	echo "Found" $keyid
	echo "Found" "trail:" $keyid >> $file_name
	echo ">> aws cloudtrail get-event-selectors --trail-name $keyid --region $1 " >> $file_name
	aws cloudtrail get-event-selectors --trail-name $keyid --region $1 >> $file_name
done

    echo ">> aws lambda list-functions --region $1" >> $file_name
	aws lambda list-functions --region $1 >> $file_name
	
	
}


6_8() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
echo "${FUNCNAME[0]} RDSスナップショットがPublicになっていないこと  $1" > $file_name
 # RDS snapshots
	echo "RDS Snapshots" >> $file_name
    LIST_OF_RDS_SNAPSHOTS=$(aws rds describe-db-snapshots --region $1 --query DBSnapshots[*].DBSnapshotIdentifier --output text)
	echo "" >> $file_name
	echo "$LIST_OF_RDS_SNAPSHOTS"  >> $file_name
	
    if [[ $LIST_OF_RDS_SNAPSHOTS ]]; then
      for rdssnapshot in $LIST_OF_RDS_SNAPSHOTS;do
        SNAPSHOT_IS_PUBLIC=$(aws rds describe-db-snapshot-attributes --region $1 --db-snapshot-identifier $rdssnapshot)

		echo ">> aws rds describe-db-snapshot-attributes --region $1 --db-snapshot-identifier $rdssnapshot " >> $file_name
		echo "$SNAPSHOT_IS_PUBLIC" >> $file_name
      done
 
    fi
	
    # RDS cluster snapshots
    LIST_OF_RDS_CLUSTER_SNAPSHOTS=$(aws rds describe-db-cluster-snapshots  --region $1 --query DBClusterSnapshots[*].DBClusterSnapshotIdentifier --output text)
    echo "RDS cluster Snapshots" >> $file_name
	echo "$LIST_OF_RDS_CLUSTER_SNAPSHOTS" >> $file_name
	
 if [[ $LIST_OF_RDS_CLUSTER_SNAPSHOTS ]]; then
	
      for rdsclustersnapshot in $LIST_OF_RDS_CLUSTER_SNAPSHOTS;do
        CLUSTER_SNAPSHOT_IS_PUBLIC=$(aws rds describe-db-cluster-snapshot-attributes  --region $1)
       
	   
	   echo ">> aws rds describe-db-cluster-snapshot-attributes  --region $1 --db-cluster-snapshot-identifier $rdsclustersnapshot " >> $file_name
		echo "$CLUSTER_SNAPSHOT_IS_PUBLIC"  >> $file_name


      done
   
    fi
	
}


6_9() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} EBSボリュームが暗号化されていること $1" > $file_name

 # EBS_DEFAULT_ENCRYPTION=$(aws ec2 get-ebs-encryption-by-default --region $1 )
 # echo ">> aws ec2 get-ebs-encryption-by-default --region $1" >> $file_name
 # echo "$EBS_DEFAULT_ENCRYPTION" >> $file_name
  
  LIST_OF_EBS_NON_ENC_VOLUMES=$(aws ec2 describe-volumes --region $1)
  echo ">>  aws ec2 describe-volumes --region $1 " >> $file_name
  echo "$LIST_OF_EBS_NON_ENC_VOLUMES" >> $file_name

   	
}


6_10() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_elb_$1.txt
touch $file_name

echo "${FUNCNAME[0]} ELBのロギングが有効になっているか $1" > $file_name

	LIST_OF_ELBS=$(aws elb describe-load-balancers --region $1 --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text|xargs -n1)
  
	echo ">> aws elb describe-load-balancers --region $1 --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text" >> $file_name
	echo "$LIST_OF_ELBS" >> $file_name
	
    if [[ $LIST_OF_ELBS  ]]; then
    
        for elb in $LIST_OF_ELBS; do
          CHECK_ELBS_LOG_ENABLED=$(aws elb describe-load-balancer-attributes --region $1 --load-balancer-name $elb)
    
	   echo '>> aws elb describe-load-balancer-attributes  --region $1 --load-balancer-name $elb' >> $file_name
	   echo "$CHECK_ELBS_LOG_ENABLED" >> $file_name

        done
    
    fi
	
	
		LIST_OF_ELBSV2=$(aws elbv2 describe-load-balancers  --region $1 --query 'LoadBalancers[*].LoadBalancerArn' --output text|xargs -n1)
		 echo ">> aws elbv2 describe-load-balancers --region $1 --query 'LoadBalancers[*].LoadBalancerArn' --output text" >> $file_name
	  echo "$LIST_OF_ELBSV2" >> $file_name
	  
    if [[ $LIST_OF_ELBSV2 ]]; then
	  
    
        for elbarn in $LIST_OF_ELBSV2; do
         CHECK_ELBSV2_LOG_ENABLED=$(aws elbv2 describe-load-balancer-attributes --region $1 --load-balancer-arn $elbarn )
         ELBV2_NAME=$(echo $elbarn|cut -d\/ -f3)
         
		 echo ">> aws elbv2 describe-load-balancer-attributes --region $1 --load-balancer-name $elbarn" >> $file_name
         echo "$CHECK_ELBSV2_LOG_ENABLED" >> $file_name
		done

    fi
}


6_11() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_all_$1.txt
touch  $file_name
echo "${FUNCNAME[0]} EBSスナップショットが暗号化されているか $1" > $file_name

# LIST_OF_EBS_NON_ENC_VOLUMES=$(aws ec2 describe-volumes --region $1)
# echo ">>  aws ec2 describe-volumes --region $1 " >> $file_name
# echo "$LIST_OF_EBS_NON_ENC_VOLUMES" >> $file_name


echo ">>  aws ec2 describe-snapshots --owner-id self  --region $1" >> $file_name
aws ec2 describe-snapshots --owner-id self  --region $1 >> $file_name
}



5_9_old() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt

echo "${FUNCNAME[0]} S3バケットのオブジェクトレベルロギングがCloudTrailで有効になっているか $1" > $file_name

 LIST_OF_BUCKETS=$(aws s3api list-buckets --region $1 --query 'Buckets[*].{Name:Name}' --output text 2>&1)
 
 
 echo ">> aws s3api list-buckets --region $1 --output text" >> $file_name
 echo "$LIST_OF_BUCKETS" >> $file_name
 
  if [[ $(echo "$LIST_OF_BUCKETS" | grep AccessDenied) ]]; then
    echo "Access Denied to buckets">> $file_name
    return
  fi
  
  LIST_OF_TRAILS=$(aws cloudtrail describe-trails --region $1 --query 'trailList[].TrailARN' --output text 2>&1)
  
  echo ">> aws cloudtrail describe-trails  --region $1 --query 'trailList[].TrailARN' --output text" >> $file_name
  echo "$LIST_OF_TRAILS"  >> $file_name
  
  if [[ $(echo "$LIST_OF_TRAILS" | grep AccessDenied) ]]; then
    echo "Access Denied trails">> $file_name
    return
  fi
  
  if [[ $LIST_OF_BUCKETS ]]; then
    for bucketName in $LIST_OF_BUCKETS; do
      if [[ $LIST_OF_TRAILS ]]; then
    
    for trail in $LIST_OF_TRAILS; do
          BUCKET_ENABLED_IN_TRAIL=$(aws cloudtrail get-event-selectors --region $1 --trail-name $trail)
         
			echo ">> aws cloudtrail get-event-selectors --region $1 --trail-name $trail" >> $file_name
			echo "$BUCKET_ENABLED_IN_TRAIL" >> $file_name

        done       
      fi
    done

  fi

}


5_11_old() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name
echo "${FUNCNAME[0]} S3バケットでデフォルトの暗号化（SSE）が有効になっており、それを強制するポリシーが設定されているか $1" > $file_name

LIST_OF_BUCKETS=$(aws s3api list-buckets  --region $1 --query Buckets[*].Name --output text|xargs -n1)
echo ">> aws s3api list-buckets  --region $1 --query Buckets[*].Name --output text|xargs -n1" >> $file_name
echo "$LIST_OF_BUCKETS">> $file_name

  if [[ $LIST_OF_BUCKETS ]]; then
    for bucket in $LIST_OF_BUCKETS;do
      BUCKET_LOCATION=$(aws s3api get-bucket-location --region $1 --bucket $bucket --output text 2>&1)
	 
      if [[ $(echo "$BUCKET_LOCATION" | grep AccessDenied) ]]; then
       
        continue
      fi
      if [[ $BUCKET_LOCATION == "None" ]]; then
        BUCKET_LOCATION="us-east-1"
      fi
      if [[ $BUCKET_LOCATION == "EU" ]]; then
        BUCKET_LOCATION="eu-west-1"
      fi

      RESULT=$(aws s3api get-bucket-encryption  --region $BUCKET_LOCATION --bucket $bucket)
      echo ">> aws s3api get-bucket-encryption  --region $BUCKET_LOCATION --bucket $bucket" >> $file_name
	  echo "$RESULT" >> $file_name

    done

  fi
  
}



5_12_old() {
echo  `date` ${FUNCNAME[0]} $1 start 
file_name=$rootpath/${FUNCNAME[0]}_$1.txt
touch $file_name 
echo "${FUNCNAME[0]} RDSインスタンスストレージが暗号化されているか $1" > $file_name
	LIST_OF_RDS_INSTANCES=$(aws rds describe-db-instances --region $1 --query 'DBInstances[*].DBInstanceIdentifier' --output text)
    echo ">> aws rds describe-db-instances --region $1 --query 'DBInstances[*].DBInstanceIdentifier'" >> $file_name
	echo "$LIST_OF_RDS_INSTANCES"  >> $file_name
 
    if [[ $LIST_OF_RDS_INSTANCES ]];then
      for rdsinstance in $LIST_OF_RDS_INSTANCES; do
        IS_ENCRYPTED=$(aws rds describe-db-instances --region $1 --db-instance-identifier $rdsinstance)
		echo ">> aws rds describe-db-instances --region $1 --db-instance-identifier $rdsinstance" >> $file_name
		echo "$IS_ENCRYPTED" >> $file_name
       
      done
  
    fi
	
}


combine_all() {
cd $rootpath

cat 1_20* > 1_20_all.txt

cat 2_1_1_* > 2_1_1_all.txt
cat 2_1_2* > 2_1_2_all.txt
cat 2_1_3* > 2_1_3_all.txt
cat 2_1_5* > 2_1_5_all.txt
cat 2_2_1_* > 2_2_1_all.txt
cat 2_3_1_* > 2_3_1_all.txt

cat 3_1_* > 3_1_all.txt
cat 3_2* > 3_2_all.txt
cat 3_3* > 3_3_all.txt
cat 3_4* > 3_3_all.txt
cat 3_5* > 3_5_all.txt
cat 3_6* > 3_6_all.txt
cat 3_7* > 3_7_all.txt
cat 3_8* > 3_8_all.txt
cat 3_9* > 3_9_all.txt
cat 3_10* > 3_10_all.txt
cat 3_11* > 3_11_all.txt

cat 4_1_* > 4_1_all.txt
cat 4_2* > 4_2_all.txt
cat 4_3* > 4_3_all.txt
cat 4_4* > 4_4_all.txt
cat 4_5* > 4_5_all.txt
cat 4_6* > 4_6_all.txt
cat 4_7* > 4_7_all.txt
cat 4_8* > 4_8_all.txt
cat 4_9* > 4_9_all.txt
cat 4_10* > 4_10_all.txt
cat 4_11* > 4_11_all.txt
cat 4_12* > 4_12_all.txt
cat 4_13* > 4_13_all.txt
cat 4_14* > 4_14_all.txt
cat 4_15* > 4_15_all.txt
cat 5_1_* > 5_1_all.txt
cat 5_1_1_* > 5_1_1_all.txt
cat 5_2* > 5_2_all.txt
cat 5_2_1_* > 5_2_1_all.txt
cat 5_3* > 5_3_all.txt
cat 5_4* > 5_4_all.txt

cat 6_1_* > 6_1_all.txt
cat 6_2* > 6_2_all.txt
cat 6_3* > 6_3_all.txt
cat 6_4* > 6_4_all.txt
cat 6_5* > 6_5_all.txt
cat 6_6* > 6_6_all.txt
cat 6_7* > 6_7_all.txt
cat 6_8* > 6_8_all.txt
cat 6_9* > 6_9_all.txt
cat 6_10* > 6_10_all.txt
cat 6_11* > 6_11_all.txt


}


1_4 "all"
1_5 "all"
1_6 "all"
1_7 "all"
1_8_9 "all"
1_10 "all"
1_12 "all"
1_14 "all"
1_15 "all"
1_16 "all"
1_17 "all"
1_19 "all" 


for i in ${region[@]}

do
echo ">>Audting $i"
echo $i

1_20 $i
2_1_1 $i
2_1_2 $i
2_1_3 $i
2_1_5 $i
2_2_1 $i
2_3_1 $i

3_1 $i
3_2 $i
3_3 $i
3_4 $i
3_5 $i
3_6 $i
3_7 $i
3_8 $i
3_9 $i
3_10 $i
3_11 $i

4_1 $i
4_2 $i
4_3 $i
4_4 $i
4_5 $i
4_6 $i
4_7 $i
4_8 $i
4_9 $i
4_10 $i
4_11 $i
4_12 $i
4_13 $i
4_14 $i
4_15 $i

5_1 $i
5_1_1 $1
5_2 $i
5_2_1 $1
5_3 $i

6_1 $i
6_2 $i
6_3 $i
6_4 $i
6_5 $i
6_6 $i
6_7 $i
6_8 $i
6_9 $i
6_10 $i
6_11 $i

done

combine_all
