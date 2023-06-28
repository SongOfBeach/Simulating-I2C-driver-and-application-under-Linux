#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include "main.h"
#include "smsoft.h"

FILE *fdChip;
void	mSecSleep(U32 mSec)
{
	struct timespec rqtp;

	rqtp.tv_sec	= mSec / 1000;
	rqtp.tv_nsec	= (mSec % 1000) * 1000*1000;

 	nanosleep(&rqtp, NULL);
}

unsigned int ioCmd(int cmd)
{
printf("cmd:%d\n",cmd);
	switch(cmd){
		case 0:
			return IOCTL_IO_WRITE_L;
		case 1:
			return IOCTL_IO_WRITE_H;
		default:
			return IOCTL_IO_TEST;
	}
}

S32 encryption_chip_msg_send(U8 *buf, U32 len)
{
	S32 retVal=0;
	U8 val[64];
	U32 i;
	
	retVal=write(fdChip,buf,len);
	if(retVal<=0){
		printf("encryption_chip_msg_send write error,retVal %d\n",retVal);
		return FAILURE;
	}
	mSecSleep(40);

	retVal= read(fdChip,val,4);
	if(retVal<=0){
		printf("encryption_chip_msg_send read error,retVal %d\n",retVal);
		return FAILURE;
	}
	mSecSleep(20);
#if 0	
	printf("buf_rev:");
	for(i=0;i<4;i++){
		printf("0x%0.2x ",val[i]);
	}printf("\n");
#endif
	if(!(val[0]==0x90&&val[1]==0x00)){
		printf("encryption_chip_msg_send msg error,0x%x 0x%x\n",val[0],val[1]);
		return FAILURE;
	}
	return SUCCESS;
}

S32 encryption_chip_msg_get(U8 *buf, U32 len, U8 *val, U32 valLen)
{
	S32 retVal=0;
	U8 msg[64];
	U32 i,msgLen;

	retVal=write(fdChip,buf,len);
	if(retVal<=0){
		printf("encryption_chip_msg_send write error,retVal %d\n",retVal);
		return FAILURE;
	}
	mSecSleep(30);

	msgLen = valLen+4;
	retVal= read(fdChip,msg,msgLen);
	if(retVal<=0){
		printf("encryption_chip_msg_send read error,retVal %d\n",retVal);
		return FAILURE;
	}
	mSecSleep(20);
#if 0	
	printf("buf_rev:");
	for(i=0;i<msgLen;i++){
		printf("0x%0.2x ",msg[i]);
	}printf("\n");
#endif
	if(!(msg[0]==0x90&&msg[1]==0x00)){
		printf("encryption_chip_msg_send msg error,%x %x\n",val[0],val[1]);
		return FAILURE;
	}
	memcpy(val,msg+4,valLen);
	return SUCCESS;
}


S32 encryption_chip_debug_set()/*正式版本需要删去恢复出厂设置命令、设置主key的命令*/
{
	U8 buf_recover[]={0x00,0x0a,0x00,0x00,0x00,0x00,0x00};
	U8 buf_mkey[]={0x00,0x30,00,00,00,00,0x10,/*key*/0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11};
	S32 retVal;
	
	retVal = encryption_chip_msg_send(buf_recover,sizeof(buf_recover));
	if(retVal<0){
		printf("encryption_chip_debug_set buf_recover send error!\n");
		return FAILURE;
	}

	retVal = encryption_chip_msg_send(buf_mkey,sizeof(buf_mkey));
	if(retVal<0){
		printf("encryption_chip_debug_set buf_mkey send error!\n");
		return FAILURE;
	}

	return SUCCESS;
}

S32 encryption_chip_judge()
{
	U8 buf_mkey[]={0x00,0x30,00,00,00,00,0x10,/*key*/0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11};

	U8 buf_version[]={0x80,0x01,0x00,0x00,0x00,0x00,0x00};
	U8 buf_random[]={0x00,0x84,0x00,0x00,0x00,0x00,0x10};
	U8 buf_verify_head[]={0x00,0x14,0x00,0x00,0x00,0x00,0x10};
	U8 buf_verify[23];
	S32 retVal,i;
	U8 myVer[]={0x56,0x30,0x33,0x31,0x31,0x37,0x30,0x39,0x31,0x32,0x30,0x30,0x31};
	U8 version[13],rand[16],hardEncoder[16],softEncoder[16];

/*compare version*/
	retVal = encryption_chip_msg_get(buf_version,sizeof(buf_version),version,sizeof(version));
	if(retVal<0){
		printf("encryption_chip_judge buf_recover get error!\n");
		return FAILURE;
	}
	if(memcmp(myVer,version,sizeof(version))){
		printf("encryption_chip_judge version error!\n");
		return FAILURE;
	}


/*get random code*/
	retVal = encryption_chip_msg_get(buf_random,sizeof(buf_random),rand,sizeof(rand));
	if(retVal<0){
		printf("encryption_chip_judge buf_recover get error!\n");
		return FAILURE;
	}
	

/*get verified code*/
	memcpy(buf_verify,buf_verify_head,sizeof(buf_verify_head));
	memcpy(buf_verify+sizeof(buf_verify_head),rand,sizeof(rand));//复制随机数到验证数中发送
	retVal  = encryption_chip_msg_get(buf_verify,sizeof(buf_verify),hardEncoder,sizeof(hardEncoder));
	if(retVal <0){
		printf("encryption_chip_judge buf_verify get error!\n");
		return FAILURE;
	}
	
	/*软编码*/
	sm4_encrypt_ecb(SM4_MODE_NOPADDING, buf_mkey+7, 16, rand, sizeof(rand), softEncoder, sizeof(softEncoder));


/*compare encode result*/
#if 1
	printf("\n----------------------------------------------------\nsoftEncoder: ");
	for(i=0;i<16;i++){
		printf("0x%0.2x ",softEncoder[i]);
	}printf("\n----------------------------------------------------\n");	

	printf("hardEncoder: ");
	for(i=0;i<16;i++){
		printf("0x%0.2x ",hardEncoder[i]);
	}printf("\n----------------------------------------------------\n\n");
#endif
	if(memcmp(softEncoder,hardEncoder,sizeof(softEncoder))){
		printf("encryption_chip_judge compare error!\n");
		return FAILURE;
	}
	return SUCCESS;
}


void	main()
{
	int mode,i,verifyTimeUp=0;
	S32 retVal=FAILURE;

	U8 buf_mkey[]={0x00,0x30,00,00,00,00,0x10,/*key*/0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11};
	U8 buf_verify_head[]={0x00,0x14,0x00,0x00,0x00,0x00,0x10};
	U8 buf_verify[23];
	U8 buf_version[]={0x80,0x01,0x00,0x00,0x00,0x00,0x00};//return 4+13bit
	U8 buf_random[]={0x00,0x84,0x00,0x00,0x00,0x00,0x10};//return 4+16bit
	U8 buf_sn[] = {0x00,0x3b,0x00,0x00,0x00,0x00,0x00,0x08};//return 4+8bit
	U8 buf_rev[]={0x00,0x0a,0x00,0x00,0x00,0x00,0x00};
	U8 val[128],rand[20],oData[16];
	U32 valLen;
	U8 ranNum[16]={0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11};


#if 0
	fdChip=open("/dev/encryptChip",O_RDWR);
	if(fdChip<0){
		printf("gpio_i2c open failed!\n");
		return;
	}


	while(retVal==FAILURE){
		if(verifyTimeUp>3)break;
		retVal = encryption_chip_debug_set();
		if(retVal<0){
			printf("encryption_chip_debug_set error!\n");
			close(fdChip);
			verifyTimeUp++;
			mSecSleep(100);
			continue;
		}

		retVal = encryption_chip_judge();
		if(retVal<0){
			printf("encryption_chip_judge error!\n");
			close(fdChip);
			verifyTimeUp++;
			mSecSleep(100);
			continue;
		}
	}

	if(verifyTimeUp>3){
		printf("this board is illegal!\n");
		return;
	}

	printf("this board is ok!\n");
	return;

#else
	struct i2c_rdwr_ioctl_data i2c_data;
	struct i2c_msg data_msgs[3];
	unsigned char buf[2];
	
	fdChip=open("/dev/i2c-0",O_RDWR);
	if(fdChip<0){
		printf("i2c-0 open failed!\n");
		return;
	}
	//ioctl(fdChip,I2C_TIMEOUT,2);
	//ioctl(fdChip,I2C_RETRIES,1);

	i2c_data.nmsgs =1;
	data_msgs[0].addr=0x60>>1;
	data_msgs[0].flags=0;
	data_msgs[0].len =2;
	data_msgs[0].buf=buf;
	data_msgs[0].buf[0]=0x00;
	data_msgs[0].buf[1]=0X01;
	i2c_data.msgs = data_msgs;
	retVal = ioctl(fdChip,I2C_RDWR,(unsigned long)&i2c_data);
	if(retVal<0)
		printf("Write I2C error%d\n",retVal);

#endif
	close(fdChip);

}

