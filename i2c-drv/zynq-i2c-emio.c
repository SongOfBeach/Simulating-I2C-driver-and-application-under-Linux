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

/*内核用dev_t类型保存设备号，高12位为主设备号代表设备类型
低20位为次设备号*/
#define major 1003 //主设备号
#define mijor 02 //次设备号
#define CLASS_NAME	"i2c_emio"
#define DEVICE_NAME "encryptChip"
#define dev_num 1 //设备号的数量

/*GPIO端口号 linux默认有1024个gpio端口，zynq有118个GPIO（54个MIO+64个EMIO）
1024-118=906对应MIO0，951便对应MIO45，此板卡的EMIO54(第一个emio)连接PS端的ds28。*/
#define GPIO_I2C_SCL 960	//MIO30	EMIO0
#define GPIO_I2C_SDA 961	//MIO31	EMIO1

/*I2C相关参数*/
#define I2C_SLAVE_ADDR 0x60	//7bit地址，1bit表示读写模式
#define DIR_OUTPUT 0
#define DIR_INPUT	1
#define HOLD_TIME 1			//高低电平钳住时间
#define WAIT_TIME 8
#define WAIT_TIME_2 550	
#define WAIT_W_R_OPTION_OK	WAIT_TIME_2	//地址下发完成后，等待芯片可以开始进行读写操作
#define WAIT_W_R_NEXT_BYTE	WAIT_TIME	//等待可以继续读写下一个字节
#define BUF_MAX_NUM 128

static dev_t devno;
static struct cdev gpio_cdev; //内核用cdev类型保存设备
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

void   gpio_write_bit_dir(unsigned int GPIO, char val)/*写值并设定方向*/
{
	gpio_direction_output(GPIO,val);
	return;
}

int   gpio_read_bit(void)
{
	return gpio_get_value(GPIO_I2C_SDA);
}

int   gpio_read_bit_dir(void)/*设定方向并读值*/
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
		if(val & 0x80) //字节高位先发送
			gpio_write_bit_dir(GPIO_I2C_SDA,1);   //送数据到数据线上   
		else
			gpio_write_bit_dir(GPIO_I2C_SDA,0);
		val <<= 1;
        waitusec(HOLD_TIME);                   
        gpio_write_bit(GPIO_I2C_SCL,1);      //置时钟信号为高电平,使数据有效   
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
		gpio_write_bit(GPIO_I2C_SCL,0); //置时钟为低电平,准备接受数据 
        waitusec(HOLD_TIME);   
        gpio_write_bit(GPIO_I2C_SCL,1);	//置时钟为高电平,使数据线数据有效   
        waitusec(HOLD_TIME); 
        value   <<=   1;   				//字节高位先读
        value   |=   gpio_read_bit();   
        waitusec(HOLD_TIME);   
        gpio_write_bit(GPIO_I2C_SCL,0);   
        waitusec(HOLD_TIME); 
	}

	return(value);
}


void   i2c_data_start(void)   /*i2c读写开始*/
{   
       gpio_write_bit_dir(GPIO_I2C_SDA,1);   //起始条件的数据信号   
       waitusec(HOLD_TIME);   
       gpio_write_bit(GPIO_I2C_SCL,1);       //起始条件时钟信号   
       waitusec(HOLD_TIME);                  //信号建立时间>4.7us   
       gpio_write_bit(GPIO_I2C_SDA,0);       //起始信号   
       waitusec(HOLD_TIME);   
       gpio_write_bit(GPIO_I2C_SCL,0);       //钳住I2C总线,   准备发送或者接受数据   
       waitusec(HOLD_TIME);   
} 

void   i2c_data_stop(void)  /*i2c读写结束*/ 
{   
      gpio_write_bit_dir(GPIO_I2C_SDA,0);   //结束条件的数据信号   
      waitusec(HOLD_TIME);   
      gpio_write_bit(GPIO_I2C_SCL,1);      //结束条件的时钟信号   
      waitusec(HOLD_TIME);   
      gpio_write_bit(GPIO_I2C_SDA,1);      //结束信号   
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
	  waitusec(WAIT_W_R_NEXT_BYTE);//读完一个字节至少等待半个周期
}   

void   i2c_No_Ack(void)   
{         
      gpio_write_bit_dir(GPIO_I2C_SDA,1);   
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,1);   
      waitusec(HOLD_TIME);   
	  gpio_write_bit(GPIO_I2C_SCL,0);   
      waitusec(HOLD_TIME);  
	  waitusec(WAIT_W_R_NEXT_BYTE);//读完一个字节至少等待半个周期
}   

unsigned char   i2c_Get_Ack(int mode)   
{         
  	  unsigned char ErrorBit = 0;
	  
      gpio_write_bit_dir(GPIO_I2C_SDA,0);   
	  gpio_set_direction(GPIO_I2C_SDA,DIR_INPUT);//设置为输入方向
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
#if 0	/*无寄存器地址*/
	gpio_write_byte(/*register addr*/);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#endif
#if 1/*等待返回ack*/
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
#if 0	/*无写地址，无寄存器地址*/
	i2c_data_start();
	gpio_write_byte(addrW);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
	gpio_write_byte(/*register addr*/);
	i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#endif
	i2c_data_start();
	gpio_write_byte(addrR);
	ErrorBit = i2c_Get_Ack(WAIT_W_R_OPTION_OK);
#if 1/*等待返回ack*/
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


//write函数，用户空间执行write时调用这个函数，完成对字符设备的写操作
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

//read函数，用户空间执行read时调用这个函数，完成对字符设备的读操作
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

//ioctl函数，用户空间执行ioctl时调用这个函数
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
	//申请gpio端口
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

//Linux使用file_operations结构访问驱动程序的函数，这个结构的每一个成员的名字都对应着一个调用
static struct file_operations gpio_i2c_file={
	.owner=THIS_MODULE,
	.open=gpio_i2c_open,
	.write=gpio_i2c_write,
	.read=gpio_i2c_read,
	.release=gpio_i2c_release,
	.unlocked_ioctl=gpio_i2c_ioctl,
};
//入口函数，驱动被加载时执行此函数
static int __init gpio_i2c_init(void)
{
	int ret;
	//生成设备号，MKDEV的操作是major<<20 + mijor。也可以直接定义
	devno = MKDEV(major,mijor);
	//静态申请设备号，静态申请的目的是使用自行定义的设备号<linux/fs.h>
	//int register_chrdev_region(dev_t first, unsigned int count, char *name);
	//第一个参数first为申请的设备号
	//第二个参数count为申请设备号的数量
	//第三个参数*name为设备名，将在sysfs和/proc/devices中出现
	ret = register_chrdev_region(devno,dev_num,DEVICE_NAME);
	if(ret < 0)
	{
		//静态申请失败进行动态申请。register_chrdev支持动态申请和静态申请
		//int alloc_chrdev_region(dev_t *dev,unsigned int -firstminor,unsigned int -count,char *name)；
		//第一个参数*dev为申请的设备号
		//第二个参数-firstminor为申请的设备号的首次设备号
		//第三个参数count为申请设备号的数量
		//第四个参数*name为设备名，将在sysfs和/proc/devices中出现
		ret = alloc_chrdev_region(&devno,mijor,dev_num,DEVICE_NAME);
		if(ret < 0)
		{
			printk("driver: alloc_chrdev_region error!\n");
			return -EFAULT;
		}
	}

	cdev_init(&gpio_cdev,&gpio_i2c_file);
	gpio_cdev.owner=THIS_MODULE;
	//注册设备到内存
	//int cdev_add(struct cdev *p, dev_t dev, unsigned count)
	//第一个参数*p为设备结构体
	//第二个参数dev为设备号
	//第二个参数dev为设备数量
	ret=cdev_add(&gpio_cdev,devno,dev_num);
	if(ret<0)
	{
		printk("driver: cdev_add error!\n");
		return -EFAULT;
	}
	//在/sys/class下创建类
	//struct class *class_create(struct module *owner, const char *name)
	//第一个参数*owner一般为THIS_MODULE
	//第二个参数为创建类的名称
	cls=class_create(THIS_MODULE,CLASS_NAME);
	//在/dev下创建设备节点
	//struct device *device_create(struct class *class, struct device *parent, dev_t d
	device_create(cls,NULL,devno,NULL,DEVICE_NAME);
	//GPIO初始化
	gpio_init();
	return 0;
}
module_init(gpio_i2c_init);
//出口函数，驱动被卸载时执行此函数
static void __exit gpio_i2c_exit(void)
{
	//释放gpio资源
	gpio_free(GPIO_I2C_SCL);
	gpio_free(GPIO_I2C_SDA);
	//销毁设备节点，即清除/dev下的设备名称
	device_destroy(cls,devno);
	//销毁class类，即清楚/sys/class下的类名
	class_destroy(cls);
	//释放cdev占用的内存
	cdev_del(&gpio_cdev);
	//释放申请的设备号
	unregister_chrdev_region(devno,dev_num);
}
module_exit(gpio_i2c_exit);

//此条不可省略
MODULE_LICENSE("GPL");

