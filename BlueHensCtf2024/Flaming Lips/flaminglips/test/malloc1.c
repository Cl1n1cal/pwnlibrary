#define fake_size 0x1fe1

int main(void)
{
    void * ptr;

    ptr = malloc (0x10);
    ptr = (void *) ((int) ptr + 24);

    *((long long*)ptr)=fake_size;

    malloc(0x2000);

    malloc(0x60);
}

