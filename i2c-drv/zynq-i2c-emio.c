#include <linux/module.h>         // Recognizes that it's a module.

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/gpio.h>
#include <linux/delay.h>
//"28 29 30 31"--"30 31"

#define IO_CONTRAL			'i'	
#define IOCTL_IO_WRITE_L	_IOW(IO_CONTRAL,0,int)
#define IOCTL_IO_WRITE_H	_IOW(IO_CONTRAL,1,int)
#define IOCTL_IO_TEST		_IOW(IO_CONTRAL,2,int)

spinlock_t	zynq_gpio_lock;
//static atomic_t canopen = ATOMIC_INIT(1);

/*�ں���dev_t���ͱ����豸�ţ���12λΪ���豸�Ŵ����豸����
��20λΪ���豸��*/
#define major 1003 //���豸��
#define mijor 02 //���豸��
#define CLASS_NAME	"i2c_emio"
#define DEVICE_NAME "encryptChip"
#define dev_num 1 //�豸�ŵ�����

/*GPIO�˿ں� linuxĬ����1024��gpio�˿ڣ�zynq��118��GPIO��54��MIO+64��EMIO��
1024-118=906��ӦMIO0��951���ӦMIO45���˰忨��EMIO54(��һ��emio)����PS�˵�ds28��*/
#define GPIO_I2C_SCL 960	//MIO30	EMIO0
#define GPIO_I2C_SDA 961	//MIO31	EMIO1

/*I2C��ز���*/
#define I2C_SLAVE_ADDR 0x60	//7bit��ַ��1bit��ʾ��дģʽ
#define DIR_OUTPUT 0
#define DIR_INPUT	1
#define HOLD_TIME 1			//�ߵ͵�ƽǯסʱ��
#define WAIT_TIME 8
#define WAIT_TIME_2 550	
#define WAIT_W_R_OPTION_OK	WAIT_TIME_2	//��ַ�·���ɺ󣬵ȴ�оƬ���Կ�ʼ���ж�д����
#define WAIT_W_R_NEXT_BYTE	WAIT_TIME	//�ȴ����Լ�����д��һ���ֽ�
#define BUF_MAX_NUM 128

static dev_t devno;
static struct cdev gpio_cdev; //�ں���cdev���ͱ����豸
static struct class* cls;

static void waitusec(int us)
{
	udelay(us);
}

static void waitmsec(int ms)
{
	mdelay(ms);
}

static int gpio_i2c_open(struct inode* inode,struct file* file)
{
	return 0;
}

static int gpio_i2c_release(struct inode* inode,struct file* file)
{
	return 0;
}

void   gpio_set_direction(unsigned int GPIO, char direction)
{
	if(direction==DIR_OUTPUT)
		gpio_direction_output(GPIO,0);
	else
		gpio_direction_input(GPIO);

	return;
}

void   gpio_write_bit(unsigned int GPIO, char val)
{
	gpio_set_value(GPIO,val);
	return;
}

void   gpio_write_bit_dir(unsigned int GPIO, char val)/*дֵ���趨����*/
{
	gpio_direction_output(GPIO,val);
	return;
}

int   gpio_read_bit(void)
{
	return gpio_get_value(GPIO_I2C_SDA);
}

int   gpio_read_bit_dir(void)/*�趨���򲢶�ֵ*/
{
	gpio_direction_input(GPIO_I2C_SDA);
 	waitusec(HOLD_TIME); 
 	return gpio_get_value(GPIO_I2C_SDA);
}

static void gpio_write_byte(unsigned char val)
{
	unsigned char i;
	unsigned char temp;

	for (i = 0; i < 8; i++) // writes byte, one bit at a time
	{
		if(val & 0x80) //�ֽڸ�λ�ȷ���
			gpio_write_bit_dir(GPIO_I2C_SDA,1);   //�����ݵ���������   
		else
			gpio_write_bit_dir(GPIO_I2C_SDA,0);
		val <<= 1;
        waitusec(HOLD_TIME);                   
        gpio_write_bit(GPIO_I2C_SCL,1);      //��ʱ���ź�Ϊ�ߵ�ƽ,ʹ������Ч   
	    waitusec(HOLD_TIME);  
	    gpio_write_bit(GPIO_I2C_SCL,0);   
        waitusec(HOLD_TIME);  
	}
}

static unsigned char gpio_read_byte(void)
{
	unsigned char i;
	unsigned char value = 0;

	gpio_write_bit(GPIO_I2C_SCL,0);
	gpio_set_direction(GPIO_I2C_SDA,DIR_INPUT);
    waitusec(HOLD_TIME);   
	for (i = 0; i < 8; i++) // writes byte, one bit at a time
	{
		gpio_write_bit(GPIO_I2C_SCL,0); //��ʱ��Ϊ�͵�ƽ,׼���������� 
        waitusec(HOLD_TIME);   
        gpio_write_bit(GPIO_I2C_SCL,1);	//��ʱ��Ϊ�ߵ�ƽ,ʹ������������Ч   
        waitusec(HOLD_TIME); 
        value   <<=   1;   				//�ֽڸ�λ�ȶ�
        value   |=   gpio_read_bit();   
        waitusec(HOLD_TIME);   
        gpio_write_bit(GPIO_I2C_SCL,0);   
        waitusec(HOLD_TIME); 
	}

	return(value);
}


void   i2c_data_start(void)   /*i2c��д��ʼ*/
{   
       gpio_write_bit_dir(GPIO_I2C_SDA,1);   //��ʼ�����������ź�   
       waitusec(HOLD_TIME);   
       gpio_write_bit(GPIO_I2C_SCL,1);       //��ʼ����ʱ���ź�   
       waitusec(HOLD_TIME);                  //�źŽ���ʱ��>4.7us   
       gpio_write_bit(GPIO_I2C_SDA,0);       //��ʼ�ź�   
       waitusec(HOLD_TIME);   
       gpio_write_bit(GPIO_I2C_SCL,0);       //ǯסI2C����,   ׼�����ͻ��߽�������   
       waitusec(HOLD_TIME);   
} 

void   i2c_data_stop(void)  /*i2c��д����*/ 
{   
      gpio_write_bit_dir(GPIO_I2C_SDA,0);   //���������������ź�   
      waitusec(HOLD_TIME);   
      gpio_write_bit(GPIO_I2C_SCL,1);      //����������ʱ���ź�   
      waitusec(HOLD_TIME);   
      gpio_write_bit(GPIO_I2C_SDA,1);      //�����ź�   
      waitusec(HOLD_TIME);  
} 

void   i2c_Ack(void)   
{         
      gpio_write_bit_dir(GPIO_I2C_SDA,0);   
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,1);   
      waitusec(HOLD_TIME);  
	  gpio_write_bit(GPIO_I2C_SCL,0);   
      waitusec(HOLD_TIME);   
	  waitusec(WAIT_W_R_NEXT_BYTE);//����һ���ֽ����ٵȴ��������
}   

void   i2c_No_Ack(void)   
{         
      gpio_write_bit_dir(GPIO_I2C_SDA,1);   
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,1);   
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,0);   
      waitusec(HOLD_TIME);  
	  waitusec(WAIT_W_R_NEXT_BYTE);//����һ���ֽ����ٵȴ��������
}   

unsigned char   i2c_Get_Ack(int mode)   
{         
  	  unsigned char ErrorBit = 0;
	  
      gpio_write_bit_dir(GPIO_I2C_SDA,0);   
	  gpio_set_direction(GPIO_I2C_SDA,DIR_INPUT);//����Ϊ���뷽��
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,1);   
      waitusec(HOLD_TIME);   
      ErrorBit   =   gpio_read_bit();  
	  gpio_write_bit(GPIO_I2C_SCL,0);   
      waitusec(HOLD_TIME);
	  waitusec(mode);
//printk("ErrorBit:%d\n",ErrorBit);
	  return ErrorBit;
}   

static int i2c_write(unsigned char *val, size_t length)
{
	unsigned char i;
	unsigned char addr=I2C_SLAVE_ADDR&0xfe;//7bit addr, 1bit wr/rd
	unsigned char ErrorBit=1;
	int timeUp=0;
	
	spin_lock_irq(&zynq_gpio_lock);

	i2c_data_start();
	gpio_write_byte(addr);
	ErrorBit = i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#if 0	/*�޼Ĵ�����ַ*/
	gpio_write_byte(/*register addr*/);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#endif
#if 1/*�ȴ�����ack*/
	while(ErrorBit){
		if(timeUp>=9){
			spin_unlock_irq(&zynq_gpio_lock);
			return -1;
		}
		timeUp++;
		if(timeUp%3==0){
			i2c_data_start();
			gpio_write_byte(addr);	
			ErrorBit = i2c_Get_Ack(WAIT_W_R_OPTION_OK);
			printk("driver: i2c_write %d error%d!\n",timeUp/3,ErrorBit);
		}
	}
#endif
	for(i=0;i<length;i++){
		gpio_write_byte(val[i]);
		ErrorBit = i2c_Get_Ack(WAIT_W_R_NEXT_BYTE);
	}
	i2c_data_stop();

	spin_unlock_irq(&zynq_gpio_lock);
	return length;
}

static int i2c_read(char *buf, size_t length)
{
	unsigned char i=0;
	unsigned char ErrorBit=1;
	unsigned char temp=0;
	unsigned char addrW=I2C_SLAVE_ADDR&0xFE;
	unsigned char addrR=I2C_SLAVE_ADDR|0x01;//7bit addr, 1bit wr/rd
	int timeUp=0;

	spin_lock_irq(&zynq_gpio_lock);
#if 0	/*��д��ַ���޼Ĵ�����ַ*/
	i2c_data_start();
	gpio_write_byte(addrW);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
	gpio_write_byte(/*register addr*/);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#endif
	i2c_data_start();
	gpio_write_byte(addrR);
	ErrorBit = i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#if 1/*�ȴ�����ack*/
	while(ErrorBit){
		if(timeUp>=9){
			spin_unlock_irq(&zynq_gpio_lock);
			return -1;
		}
		timeUp++;
		if(timeUp%3==0){
			i2c_data_start();
			gpio_write_byte(addrR);	
			ErrorBit = i2c_Get_Ack(WAIT_W_R_OPTION_OK);
			printk("driver: i2c_read %d ack %d!\n",timeUp/3,ErrorBit);
		}
	}
#endif
	for(i=0;i<length;i++){
		buf[i] = gpio_read_byte();
		i2c_Ack();
		//printk("%x\n",buf[i]);
	}
	i2c_No_Ack();
	i2c_data_stop();

	spin_unlock_irq(&zynq_gpio_lock);

	return length;
}


//write�������û��ռ�ִ��writeʱ���������������ɶ��ַ��豸��д����
ssize_t gpio_i2c_write(struct file *filp, const char *buffer, size_t length, loff_t *offset)
{
	int ret,len;
	int8_t kbuf[BUF_MAX_NUM];

	if(length>BUF_MAX_NUM)
	{
		printk("driver: kernel write %d overflow \n",length);
		return -1;
	}

	ret = copy_from_user(kbuf,buffer,length);
	if(ret < 0)
	{
		printk("driver: kernel write error \n");
		return -1;
	}
	len = i2c_write(kbuf,length);

	return len;
}

//read�������û��ռ�ִ��readʱ���������������ɶ��ַ��豸�Ķ�����
ssize_t gpio_i2c_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	int ret,len;
	int8_t kbuf[BUF_MAX_NUM];

	if(length>BUF_MAX_NUM)
	{
		printk("driver: kernel read %d overflow \n",length);
		return -1;
	}

	len =i2c_read(kbuf,length);
	if(len < 0 || len>BUF_MAX_NUM)
	{
		printk("driver: kernel read len %d error\n",len);
		return -1;
	}


	ret = copy_to_user(buffer,kbuf,len);
	if(ret < 0)
	{
		printk("driver: kernel read error\n");
		return -1;
	}
	return len;
}

/*---------------------- TEST START ----------------------*/
int gpio_write_test(unsigned long arg)
{
	int val_sda=0;
printk("arg:%d\t\n",arg);
	gpio_write_bit(GPIO_I2C_SDA,arg);
	waitusec(100);
	val_sda = gpio_read_bit();
printk("val_sda:%d\n",val_sda);
	return 0;
}
/*----------------------- TEST END -----------------------*/

//ioctl�������û��ռ�ִ��ioctlʱ�����������
long gpio_i2c_ioctl(struct file *file,unsigned int cmd,unsigned long arg)
{
	int ret;
	
	switch(cmd)
	{
		case IOCTL_IO_WRITE_L:
			gpio_write_test(0);
			break;
		case IOCTL_IO_WRITE_H:
			gpio_write_test(1);
			break;
		case IOCTL_IO_TEST:
			break;
		default:
			return -1;
	}
	return 0;
}

static void gpio_init(void)
{
	int ret;
	//����gpio�˿�
	ret = gpio_request(GPIO_I2C_SCL,"GPIO_I2C_SCL_PORT\n");
	if(ret>0)
	{
		printk("driver: gpio_request GPIO_I2C_SCL_PORT data error\n");
	}
	ret = gpio_request(GPIO_I2C_SDA,"GPIO_I2C_SDA_PORT\n");
	if(ret>0)
	{
		printk("driver: gpio_request GPIO_I2C_SDA_PORT data error\n");
	}
	gpio_set_direction(GPIO_I2C_SCL,DIR_OUTPUT);
}

//Linuxʹ��file_operations�ṹ������������ĺ���������ṹ��ÿһ����Ա�����ֶ���Ӧ��һ������
static struct file_operations gpio_i2c_file={
	.owner=THIS_MODULE,
	.open=gpio_i2c_open,
	.write=gpio_i2c_write,
	.read=gpio_i2c_read,
	.release=gpio_i2c_release,
	.unlocked_ioctl=gpio_i2c_ioctl,
};
//��ں���������������ʱִ�д˺���
static int __init gpio_i2c_init(void)
{
	int ret;
	//�����豸�ţ�MKDEV�Ĳ�����major<<20 + mijor��Ҳ����ֱ�Ӷ���
	devno = MKDEV(major,mijor);
	//��̬�����豸�ţ���̬�����Ŀ����ʹ�����ж�����豸��<linux/fs.h>
	//int register_chrdev_region(dev_t first, unsigned int count, char *name);
	//��һ������firstΪ������豸��
	//�ڶ�������countΪ�����豸�ŵ�����
	//����������*nameΪ�豸��������sysfs��/proc/devices�г���
	ret = register_chrdev_region(devno,dev_num,DEVICE_NAME);
	if(ret < 0)
	{
		//��̬����ʧ�ܽ��ж�̬���롣register_chrdev֧�ֶ�̬����;�̬����
		//int alloc_chrdev_region(dev_t *dev,unsigned int -firstminor,unsigned int -count,char *name)��
		//��һ������*devΪ������豸��
		//�ڶ�������-firstminorΪ������豸�ŵ��״��豸��
		//����������countΪ�����豸�ŵ�����
		//���ĸ�����*nameΪ�豸��������sysfs��/proc/devices�г���
		ret = alloc_chrdev_region(&devno,mijor,dev_num,DEVICE_NAME);
		if(ret < 0)
		{
			printk("driver: alloc_chrdev_region error!\n");
			return -EFAULT;
		}
	}

	cdev_init(&gpio_cdev,&gpio_i2c_file);
	gpio_cdev.owner=THIS_MODULE;
	//ע���豸���ڴ�
	//int cdev_add(struct cdev *p, dev_t dev, unsigned count)
	//��һ������*pΪ�豸�ṹ��
	//�ڶ�������devΪ�豸��
	//�ڶ�������devΪ�豸����
	ret=cdev_add(&gpio_cdev,devno,dev_num);
	if(ret<0)
	{
		printk("driver: cdev_add error!\n");
		return -EFAULT;
	}
	//��/sys/class�´�����
	//struct class *class_create(struct module *owner, const char *name)
	//��һ������*ownerһ��ΪTHIS_MODULE
	//�ڶ�������Ϊ�����������
	cls=class_create(THIS_MODULE,CLASS_NAME);
	//��/dev�´����豸�ڵ�
	//struct device *device_create(struct class *class, struct device *parent, dev_t d
	device_create(cls,NULL,devno,NULL,DEVICE_NAME);
	//GPIO��ʼ��
	gpio_init();
	return 0;
}
module_init(gpio_i2c_init);
//���ں�����������ж��ʱִ�д˺���
static void __exit gpio_i2c_exit(void)
{
	//�ͷ�gpio��Դ
	gpio_free(GPIO_I2C_SCL);
	gpio_free(GPIO_I2C_SDA);
	//�����豸�ڵ㣬�����/dev�µ��豸����
	device_destroy(cls,devno);
	//����class�࣬�����/sys/class�µ�����
	class_destroy(cls);
	//�ͷ�cdevռ�õ��ڴ�
	cdev_del(&gpio_cdev);
	//�ͷ�������豸��
	unregister_chrdev_region(devno,dev_num);
}
module_exit(gpio_i2c_exit);

//��������ʡ��
MODULE_LICENSE("GPL");

