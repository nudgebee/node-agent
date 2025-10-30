// AMQP 0-9-1 Protocol Specification
// https://www.rabbitmq.com/protocol.html

#define RABBITMQ_FRAME_TYPE_METHOD 1
#define RABBITMQ_FRAME_END 0xCE

#define RABBITMQ_CLASS_BASIC 60
#define RABBITMQ_METHOD_PUBLISH 40
#define RABBITMQ_METHOD_DELIVER 60

static __always_inline
int is_rabbitmq_connection(char *buf, __u64 buf_size) {
    if (buf_size < 8) {
        return 0;
    }
    char magic[8];
    bpf_read(buf, magic);
    if (magic[0] == 'A' && magic[1] == 'M' && magic[2] == 'Q' && magic[3] == 'P') {
        return 1;
    }
    return 0;
}

static __always_inline
int rabbitmq_method_is(char *buf, __u64 buf_size, __u16 expected_method) {
    if (buf_size < 12) {
        return 0;
    }
    __u8 type = 0;
    bpf_read(buf, type);
    if (type != RABBITMQ_FRAME_TYPE_METHOD) {
        return 0;
    }

    __u32 size = 0;
    bpf_read(buf+3, size);
    size = bpf_htonl(size);
    if (size > MAX_PAYLOAD_SIZE) {
        return 0;
    }
    if (7 + size + 1 > buf_size) {
        return 0;
    }
    __u8 end = 0;
    TRUNCATE_PAYLOAD_SIZE(size);
    bpf_read(buf+7+size, end);
    if (end != RABBITMQ_FRAME_END) {
        return 0;
    }

    __u16 class = 0;
    bpf_read(buf+7, class);
    if (bpf_htons(class) != RABBITMQ_CLASS_BASIC) {
        return 0;
    }

    __u16 method = 0;
    bpf_read(buf+9, method);
    if (bpf_htons(method) != expected_method) {
        return 0;
    }

    return 1;
}

static __always_inline
int is_rabbitmq_produce(char *buf, __u64 buf_size) {
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_PUBLISH);
}

static __always_inline
int is_rabbitmq_consume(char *buf, __u64 buf_size) {
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_DELIVER);
}

static __always_inline
int is_amqp_frame(char *buf, __u64 buf_size) {
    if (buf_size < 8) {
        return 0;
    }
    
    // Check for AMQP frame structure: type + channel + size + payload + end
    __u8 frame_type = 0;
    bpf_read(buf, frame_type);
    
    // Valid AMQP frame types
    if (frame_type != RABBITMQ_FRAME_TYPE_METHOD && 
        frame_type != 2 && // Content header frame
        frame_type != 3 && // Content body frame
        frame_type != 8) { // Heartbeat frame
        return 0;
    }
    
    __u32 size = 0;
    bpf_read(buf+3, size);
    size = bpf_htonl(size);
    if (size > MAX_PAYLOAD_SIZE) {
        return 0;
    }
    if (7 + size + 1 > buf_size) {
        return 0;
    }
    __u8 end = 0;
    TRUNCATE_PAYLOAD_SIZE(size);
    bpf_read(buf+7+size, end);
    if (end != RABBITMQ_FRAME_END) {
        return 0;
    }
    return 1;
}

static __always_inline
int is_amqp_method_frame(char *buf, __u64 buf_size) {
    if (buf_size < 12) {
        return 0;
    }
    
    __u8 frame_type = 0;
    bpf_read(buf, frame_type);
    if (frame_type != RABBITMQ_FRAME_TYPE_METHOD) {
        return 0;
    }
    
    __u32 size = 0;
    bpf_read(buf+3, size);
    size = bpf_htonl(size);
    if (size > MAX_PAYLOAD_SIZE || size < 4) {
        return 0;
    }
    if (7 + size + 1 > buf_size) {
        return 0;
    }
    
    __u8 end = 0;
    TRUNCATE_PAYLOAD_SIZE(size);
    bpf_read(buf+7+size, end);
    if (end != RABBITMQ_FRAME_END) {
        return 0;
    }
    
    // Check if it's a valid AMQP method (any class/method combination)
    __u16 class = 0;
    __u16 method = 0;
    bpf_read(buf+7, class);
    bpf_read(buf+9, method);
    
    class = bpf_htons(class);
    method = bpf_htons(method);
    
    // Valid AMQP classes include: Connection(10), Channel(20), Exchange(40), Queue(50), Basic(60), Tx(90)
    if ((class >= 10 && class <= 90) && method > 0) {
        return 1;
    }
    
    return 0;
}
