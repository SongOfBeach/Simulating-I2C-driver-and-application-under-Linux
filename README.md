# 基本情况

使用cpu的**emio**引脚模拟i2c协议，与应用层芯片进行通信。

**i2c-drv**：emio模拟i2c的驱动；

**i2c-app**：与上层某加密芯片进行通信的模块；



# 版本记录

### i2c-drv

20210730:  基本实现emio i2c读写，写入授权芯片验证成功，读取还存在问题； 
20210802:  实现I2C读写，加密流程验证成功，关闭打印；
20210803:  修改加锁后未解锁导致崩溃的问题；

### i2c-app

20210730:  I2C上层应用；
20210803:  实现加密芯片验证流程，封装函数；