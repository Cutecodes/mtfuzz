
#define MMIO_SR    0x20000010
#define MMIO_LEN   0x20000014
#define MMIO_DATA1 0x20000020
#define MMIO_DATA2 0x20000024
#define RX_MASK    0x1
#define DX_MASK    0x2
int buffer[1000];

int read_data(int addr) {
    return *(int*)addr;
}

void init_interrupt(){
    int *ipp;
    ipp = (int*)0x80000090;
    *ipp= 0x100;
    ipp = (int*)0x800000A8;
    *ipp= 0x7;
}


void start_timer(){
    int *ipp;
    ipp = (int*)0x80000044;
    *ipp= 0x10000;
    ipp = (int*)0x80000040;
    *ipp= 0x0;
    ipp = (int*)0x80000048;
    *ipp= 0x7;
}

void test_app(){
    int len = 5;
    int checksum = 0;

    int buff[10];
    
    for(int i=0;i<len;i++){
       buff[i] = read_data(MMIO_DATA1);
    }
    
    for(int i=0;i<len-1;i++){
       checksum = checksum+buff[i];
    }
     
    if(buff[len-1] != checksum){
       return;
    }
    
    if ((buff[0] & 0xffffffff)==0x55555555) {
       *(int*)0 = 999; // bug here
       buff[0] = 1;
    }
    
}

int main(){
    init_interrupt();
    start_timer();

    while(1){
      test_app();
    };
    return 0;
}

void c_int(){
    int a = 0;
    int b = 0;
    int c = a + b;
    return;
}
