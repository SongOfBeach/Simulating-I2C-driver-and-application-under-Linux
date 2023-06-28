obj-m:=i2c-emio.o
i2c-emio-objs:=zynq-i2c-emio.o
	KDIR := /home/jointbest/Downloads/peta_prj/ax_peta_h11_i2c/build/tmp/work/plnx_arm-xilinx-linux-gnueabi/linux-xlnx/4.9-xilinx-v2017.4+gitAUTOINC+b450e900fd-r0/linux-plnx_arm-standard-build/
	#KDIR := /home/jointbest/Downloads/peta_prj/ax_peta_h11_emio/build/tmp/work/plnx_arm-xilinx-linux-gnueabi/linux-xlnx/4.9-xilinx-v2017.4+gitAUTOINC+b450e900fd-r0/linux-plnx_arm-standard-build
	KOPT  = ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
	
all:
	make -C $(KDIR) $(KOPT) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.symvers *.cmd *.cmd.o   modules.order  i2c-emio.mod.c
