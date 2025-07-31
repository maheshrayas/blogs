#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_STRING_LEN 64

SEC("uprobe/main.hello_int")
int handle_hello_int(struct pt_regs *ctx)
{
    int x = (int)ctx->ax;
    bpf_printk("===Function Arguments ===\n");
    bpf_printk("x (int) = x=%llu\n", x);
    return 0;
}

SEC("uprobe/main.hello_int_string")
int handle_hello_int_string(struct pt_regs *ctx)
{
    // For hello(x int, y string)
    int x = (int)ctx->ax;            // First argument (int)
    void *str_ptr = (void *)ctx->bx; // String data pointer
    long str_len_raw = ctx->cx;      // String length (as long)

    // bpf_printk("=== Function Arguments ===\n");
    // bpf_printk("x (int) = %d\n", x);
    // bpf_printk("y.Data (ptr) = 0x%lx\n", (unsigned long)str_ptr);
    // bpf_printk("y.Len (raw) = %ld\n", str_len_raw);

    // Safe bounds checking for BPF verifier
    if (str_ptr != NULL && str_len_raw > 0)
    {

        char str_buf[MAX_STRING_LEN + 1] = {0};

        // Read with explicit bounds check
        if (str_len_raw < 0 || str_len_raw > sizeof(str_buf))
        {
            bpf_printk("Invalid string length: %ld\n", str_len_raw);
            return 0;
        }
        long ret = bpf_probe_read_user(str_buf, str_len_raw, str_ptr);
        if (ret < 0)
        {
            bpf_printk("Failed to read string\n");
            return 0;
        }

        if (str_len_raw < sizeof(str_buf))
        {
            str_buf[str_len_raw] = '\0';
        }

        bpf_printk("Int is:%d and String: %s\n", x, str_buf);
        return 0;
    }
    else
    {
        bpf_printk("Invalid string pointer or length\n");
    }

    return 0;
}

struct animals_data
{
    // Name string (ptr + len)
    void *name_ptr;
    long name_len;

    // Species string (ptr + len)
    void *species_ptr;
    long species_len;

    // Age int
    long age;

    // Weight float64
    double weight;

    // IsWild bool (+ padding)
    char is_wild;
    char padding[7];
};
SEC("uprobe/handle_hello_struct_pointer")
int handle_hello_struct_pointer(struct pt_regs *ctx)
{
    // Get the pointer to Animals struct from RAX
    void *animals_ptr = (void *)PT_REGS_RC(ctx); // RAX register

    if (!animals_ptr)
    {
        bpf_printk("Null pointer received\n");
        return 0;
    }
    // Define struct layout matching Go's Animals struct

    struct animals_data animals;
    // Read the entire struct from user memory
    if (bpf_probe_read_user(&animals, sizeof(animals), animals_ptr) != 0)
    {
        bpf_printk("Failed to read Animals struct\n");
        return 0;
    }

    // Read and print Name
    char name_buf[64] = {0};
    long str_len_raw = animals.name_len;
    if (str_len_raw < 0 || str_len_raw > sizeof(name_buf))
    {
        bpf_printk("Invalid string length: %ld\n", str_len_raw);
        return 0;
    }

    if (animals.name_len > 0 && animals.name_len < sizeof(name_buf))
    {
        if (bpf_probe_read_user(name_buf, str_len_raw, animals.name_ptr) == 0)
        {
            name_buf[str_len_raw] = '\0';
            bpf_printk("Name: %s (len=%ld)\n", name_buf, animals.name_len);
        }
    }

    char species_buf[64] = {0};
    long str_len_species_raw = animals.species_len;
    if (str_len_species_raw < 0 || str_len_species_raw > sizeof(name_buf))
    {
        bpf_printk("Invalid string length: %ld\n", str_len_species_raw);
        return 0;
    }
    if (animals.species_len > 0 && animals.species_len < sizeof(species_buf))
    {
        if (bpf_probe_read_user(species_buf, str_len_species_raw, animals.species_ptr) == 0)
        {
            species_buf[str_len_species_raw] = '\0';
            bpf_printk("Species: %s (len=%ld)\n", species_buf, animals.species_len);
        }
    }

    // Print other fields
    bpf_printk("Age: %ld\n", animals.age);
    bpf_printk("Weight: %lf\n", animals.weight);
    bpf_printk("IsWild: %s\n", animals.is_wild ? "true" : "false");

    return 0;
}

SEC("uprobe/handle_hello_struct_value")
int handle_hello_struct_value(struct pt_regs *ctx)
{
    void *name_ptr = (void *)PT_REGS_RC(ctx); // RAX
    long name_len = (long)ctx->bx;            // RBX
    void *species_ptr = (void *)ctx->cx;      // RCX
    long species_len = (long)ctx->di;         // RDI

    // Extract other fields
    long age = (long)ctx->si;     // RSI
    long is_wild = (long)ctx->r8; // R8

    char name_buf[64] = {0};
    int str_len_raw = name_len;

    if (str_len_raw < 0 || str_len_raw >= sizeof(name_buf))
    {
        bpf_printk("Invalid string length: %ld\n", str_len_raw);
        return 0;
    }

    // Use unsigned type and apply bitmask to help verifier
    u32 safe_len = (u32)str_len_raw;
    safe_len &= 0x3F; // Mask to ensure it's <= 63 (0x3F = 63)

    if (safe_len >= sizeof(name_buf))
    {
        return 0; // Double check after masking
    }

    if (bpf_probe_read_user(name_buf, safe_len, name_ptr) != 0)
    {
        bpf_printk("Failed to read string\n");
        return 0;
    }

    bpf_printk("Name: %s (len=%d)\n", name_buf, safe_len);

    char species_buf[64] = {0};
    int spe_str_len_raw = species_len;

    if (spe_str_len_raw < 0 || spe_str_len_raw >= sizeof(species_buf))
    {
        bpf_printk("Invalid string length: %ld\n", spe_str_len_raw);
        return 0;
    }

    // Use unsigned type and apply bitmask to help verifier
    u32 species_safe_len = (u32)spe_str_len_raw;
    species_safe_len &= 0x3F; // Mask to ensure it's <= 63 (0x3F = 63)

    if (species_safe_len >= sizeof(species_buf))
    {
        return 0; // Double check after masking
    }

    if (bpf_probe_read_user(species_buf, species_safe_len, name_ptr) != 0)
    {
        bpf_printk("Failed to read string\n");
        return 0;
    }
    bpf_printk("Species Name: %s (Species len=%d)\n", species_buf, species_safe_len);
    bpf_printk("Age: %ld\n", age);
    bpf_printk("IsWild: %s\n", is_wild ? "true" : "false");

    return 0;
}
