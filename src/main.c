#include <bfu.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LOCK_TIMEOUT "900"

typedef enum {
    MODE_NONE,
    MODE_CREATE,
    MODE_EDIT,
    MODE_SEARCH
} mode;

void print_usage() {
    printf("USAGE: bwclient [-c|--create=<url>] [-e|--edit=<url>] [-s|--search=<url>]\n");
    printf("Options:\n");
    printf("-c --create=[<url>]        Create a new entry in bitwarden. Can optionally take an URL as argument\n");
    printf("-e --edit=[<url>]          Search and edit an entry in bitwarden. Can optionally take an URL as argument\n");
    printf("-s --search=[<url>]        Search an entry in bitwarden. Can optionally take an URL as argument\n");
}

bool read_password(bfu_string *out) {
    bfu_process rofi = { .stdout_fd = bfu_process_fd_pipe() };
    i32 status = bfu_process_run_sync(&rofi, "rofi", "-dmenu", "-password", "-p", "Vault Password");
    bool res = true;
    if (status != 0) {
        res = false;
        goto end;
    }
    bfu_process_fd_read(out, rofi.stdout_fd);
    out->data[--out->size]  = '\0'; // Remove trailing \n
end:
    bfu_process_close(&rofi);
    return res;
}

typedef struct {
    bfu_string id;
    bfu_string name;
    bfu_string username;
    bfu_string password;
    bfu_string totp;
} bw_item;

DEFINE_BFU_ARRAY_DELETE(bfu_string)
DEFINE_BFU_ARRAY_DELETE(bw_item)

static bfu_string session = {0};

bool bw_try_unlock() {
    bfu_string_f out = {0};
    bfu_process keyctl = { .stdout_fd = bfu_process_fd_pipe() };
    i32 status = bfu_process_run_sync(&keyctl, "keyctl", "request", "user", "bw_session");
    if (status != 0) {
        bfu_process_close(&keyctl);
        return false;
    }
    bfu_process_fd_read(&out, keyctl.stdout_fd);
    out.data[--out.size] = '\0';
    status = bfu_process_run_sync(&keyctl, "keyctl", "pipe", out.data);
    out.size = 0;
    bfu_process_fd_read(&session, keyctl.stdout_fd);
    return status == 0;
}

bool bw_unlock(bfu_string password) {
    bfu_process bw = { .stdout_fd = bfu_process_fd_pipe() };

    i32 status = bfu_process_run_sync(&bw, "bw", "unlock", password.data, "--raw"); 
    bfu_process_fd_read(&session, bw.stdout_fd);
    bfu_process_close(&bw);
    if (status == 0) {
        bfu_process keyctl = { .stdout_fd = bfu_process_fd_pipe() };
        bfu_string_f out = {0};
        bfu_process_run_sync(&keyctl, "keyctl", "add", "user", "bw_session", session.data, "@u");
        bfu_process_fd_read(&out, keyctl.stdout_fd);
        out.data[--out.size] = '\0';
        keyctl.stdout_fd = bfu_process_fd_none();
        bfu_process_run_sync(&keyctl, "keyctl", "timeout", out.data, LOCK_TIMEOUT);
    }
    return status == 0;
}

bfu_array(bw_item) bw_items(char *arg) {
    bfu_array(bw_item) items = NULL;
    bfu_process bw = { .stdout_fd = bfu_process_fd_pipe() };
    
    if (arg) {
        bfu_process_run(&bw, "bw", "--session", session.data, "--nointeraction","list", "items", "--search", arg); 
    }
    else {
        bfu_process_run(&bw, "bw", "--session", session.data, "--nointeraction", "list", "items"); 
    }
    bfu_process jq = { .stdin_fd = bfu_process_fd_from_fd(bw.stdout_fd.fd), .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run_sync(&jq, "jq", "-r", ".[] | [.id, .name, .login.username, .login.password, .login.totp] | @tsv");
    bfu_string_f out = {0};
    bfu_process_fd_read(&out, jq.stdout_fd);
    bfu_process_close(&bw);
    bfu_process_close(&jq);

    bfu_array_f(bfu_string) lines = bfu_string_split(&out, '\n');
    for (u64 i = 0; i < bfu_array_size(lines); i++) {
        bfu_array_f(bfu_string) parts = bfu_string_split(&lines[i], '\t');
        if (bfu_array_size(parts) == 5) {
            bfu_array_push(items, ((bw_item) {parts[0], parts[1], parts[2], parts[3], parts[4]}));
        } else {
            for(u64 j = 0; j <  bfu_array_size(parts); j++) {
                bfu_string_delete(&parts[j]);
            }
        }
        bfu_string_delete(&lines[i]);
    }
    return items;
}

bfu_string bw_get(bfu_string id, bfu_string option) {
    bfu_process bw = { .stdout_fd = bfu_process_fd_pipe() };
    bfu_string out = {0};
    bfu_process_run(&bw, "bw", "--session", session.data, "--nointeraction", "get", option.data, id.data); 
    bfu_process_fd_read(&out, bw.stdout_fd);
    bfu_process_close(&bw);
    if (bfu_process_wait(&bw) != 0) {
        bfu_string_delete(&out);
        return (bfu_string) {0};
    }
    return out;
}

bfu_string bw_generate() {
    bfu_process bw = { .stdout_fd = bfu_process_fd_pipe() };
    bfu_string out = {0};
    bfu_process_run(&bw, "bw", "generate", "-ulns", "--length", "18");
    bfu_process_fd_read(&out, bw.stdout_fd);
    bfu_process_close(&bw);
    if (bfu_process_wait(&bw) != 0) {
        bfu_string_delete(&out);
        return (bfu_string) {0};
    }
    return out;
}

void bw_save(bw_item item) {
    bfu_process bw = { .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run(&bw, "bw", "--session", session.data, "--nointeraction", "get", "item", item.id.data); 

    bfu_process jq = { .stdin_fd = bfu_process_fd_from_fd(bw.stdout_fd.fd), .stdout_fd = bfu_process_fd_pipe() };
    bfu_string_f jq_arg = {0};
    bfu_string_format(&jq_arg, ".login.username=\"%s\" | .login.password=\"%s\"", item.username.data, item.password.data);
    if (item.totp.size > 0) {
        bfu_string_push_format(&jq_arg, " | .login.totp=\"%s\"", item.totp.data);
    }
    bfu_process_run(&jq, "jq", jq_arg.data); 
    
    bfu_process bw_encode = { .stdin_fd = bfu_process_fd_from_fd(jq.stdout_fd.fd), .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run(&bw_encode, "bw", "encode"); 
    
    bfu_process bw_save = { .stdin_fd = bfu_process_fd_from_fd(bw_encode.stdout_fd.fd) };
    bfu_process_run_sync(&bw_save, "bw", "--session", session.data, "--nointeraction", "edit", "item", item.id.data); 
}

void bw_create(bw_item item) {
    bfu_string_f json  = {0};
    if (!item.totp.data) {
        bfu_string_push(&item.totp, "\0");
    }

    bfu_string_format(&json, "{\"passwordHistory\":[],\"revisionDate\":null,\"creationDate\":null,\"deletedDate\":null,\"archivedDate\":null,\"organizationId\":null,\"collectionIds\":null,\"folderId\":null,\"type\":1,\"name\":\"%s\",\"notes\":null,\"favorite\":false,\"fields\":[],\"login\":{\"username\": \"%s\", \"password\": \"%s\", \"totp\": \"%s\", \"uris\": [{\"uri\": \"%s\"}]},\"secureNote\":null,\"card\":null,\"identity\":null,\"sshKey\":null,\"reprompt\":0}",
                      item.name.data, item.username.data, item.password.data, item.totp.data, item.name.data);
    bfu_process bw_encode = { .stdin_fd = bfu_process_fd_pipe(), .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run(&bw_encode, "bw", "encode"); 
    bfu_process_fd_write(bw_encode.stdin_fd, &json);
    close(bw_encode.stdin_fd.fd);
    
    bfu_process bw_save = { .stdin_fd = bfu_process_fd_from_fd(bw_encode.stdout_fd.fd) };
    bfu_process_run_sync(&bw_save, "bw", "--session", session.data, "--nointeraction", "create", "item"); 
}

void free_bw_items(bfu_array(bw_item) items) {
    for (u64 i = 0; i < bfu_array_size(items); i++) {
        bfu_string_delete(&items[i].id);
        bfu_string_delete(&items[i].name);
        bfu_string_delete(&items[i].username);
    }
}

i64 rofi_items(bfu_array(bw_item) items) {
    bfu_string_f in = {0};
    for (u64 i = 0; i < bfu_array_size(items); i++) {
        bfu_string_push_format(&in, "%s - %s\n", items[i].name.data, items[i].username.data);
    }
    bfu_process rofi = { .stdin_fd = bfu_process_fd_pipe(), .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run(&rofi, "rofi", "-dmenu", "-p", "Select item", "-format", "i");
    bfu_process_fd_write(rofi.stdin_fd, &in);
    i32 status = bfu_process_wait(&rofi);
    if (status != 0) { 
        bfu_process_close(&rofi);
        return -1;
    }
    bfu_string_f out = {0};
    bfu_process_fd_read(&out, rofi.stdout_fd);
    bfu_process_close(&rofi);
    return atol(out.data);
}

bfu_string rofi_dmenu(const char *prompt, ...) {
    bfu_string_f in = {0};
    va_list ap;
    va_start(ap, prompt);
    char *arg = va_arg(ap, char*);
    while (arg != NULL) {
        bfu_string_push(&in, arg);
        bfu_string_push(&in, "\n");
        arg = va_arg(ap, char*);
    }
    va_end(ap);

    bfu_process rofi = { .stdin_fd = bfu_process_fd_pipe(), .stdout_fd = bfu_process_fd_pipe() };
    bfu_process_run(&rofi, "rofi", "-dmenu", "-p", prompt, "-only-match");
    bfu_process_fd_write(rofi.stdin_fd, &in);
    close(rofi.stdin_fd.fd);
    bfu_string out = {0};
    bfu_process_fd_read(&out, rofi.stdout_fd);
    i32 status = bfu_process_wait(&rofi);
    bfu_process_close(&rofi);
    if (status != 0) { 
        bfu_string_delete(&out);
    }
    out.data[--out.size] = '\0';
    return out;
}

bfu_string rofi_form(const char *prompt, const char *default_value) {
    bfu_process rofi = { .stdout_fd = bfu_process_fd_pipe() };
    i32 status = bfu_process_run_sync(&rofi, "rofi", "-dmenu", "-p", prompt, "-filter", default_value);
    bfu_string out = {0};
    bfu_process_fd_read(&out, rofi.stdout_fd);
    bfu_process_close(&rofi);
    if (status != 0) { 
        if (default_value) {
            out.size = 0;
            bfu_string_push(&out, (char*) default_value);
        } else {
            bfu_string_delete(&out);
        }
        return out;
    }
    out.data[--out.size] = '\0';
    return out;
}

void rofi_error(const char *err) {
    bfu_process rofi = {0};
    bfu_process_run_sync(&rofi, "rofi", "-e", err);
}

void wl_copy(bfu_string txt) {
    bfu_process p = { .stdin_fd = bfu_process_fd_pipe() };
    bfu_process_run(&p, "wl-copy");
    bfu_process_fd_write(p.stdin_fd, &txt);
    bfu_process_wait(&p);
}

i8 edit_form(bw_item *item) {
    bfu_string_f option = rofi_dmenu("Which item you want to edit?", "username", "password", "totp", "cancel", "done", NULL);
    if (option.size == 0 || bfu_string_eq(&option, "cancel")) {
        return 0;
    }
    if (bfu_string_eq(&option, "done")) {
        return 1;
    }
    if (bfu_string_eq(&option, "username")) {
        bfu_string value = rofi_form("What is the new username", item->username.data);
        bfu_string_delete(&item->username);
        item->username = value;
    }
    if (bfu_string_eq(&option, "totp")) {
        bfu_string value = rofi_form("What is the new totp string", item->totp.data);
        bfu_string_delete(&item->totp);
        item->totp = value;
    }
    if (bfu_string_eq(&option, "password")) {
        bfu_string_f pw_option = rofi_dmenu("Provide password or generate?", "provide password", "generate", NULL);
        if (option.size == 0) {
            return 2;
        }
        if (bfu_string_eq(&pw_option, "provide password")) {
            bfu_string value = rofi_form("What is the new password", NULL);
            if (value.size == 0) {
                bfu_string_delete(&value);
                return 2;
            }
        
            bfu_string_delete(&item->password);
            item->password = value;
        }
        else {
            bfu_string value = bw_generate();
            bfu_string_delete(&item->password);
            item->password = value;
        }
    }
    return 2;
}

i32 main (i32 argc, char **argv) {
    struct option opts[] = {
        { "create", required_argument, NULL, 'c' },
        { "edit",   optional_argument, NULL, 'e' },
        { "search", optional_argument, NULL, 's' },
        { "help",   no_argument,       NULL, 'h' },
        {0}
    };
    i32 opt;
    mode mode = MODE_NONE;
    char *arg = NULL;
    while ((opt = getopt_long(argc, argv, "he::c:s::", opts, NULL)) != -1) {
        switch(opt) {
        case 'h': 
            print_usage();
            return 1;
        case 'c':
            mode = MODE_CREATE;
            if (optarg) arg = strdup(optarg);
            break;
        case 'e':
            mode = MODE_EDIT;
            if (optarg) arg = strdup(optarg);
            break;
        case 's':
            mode = MODE_SEARCH;
            if (optarg) arg = strdup(optarg);
            break;
        default:
            print_usage();
            return 2;
        }
    }

    if (mode == MODE_NONE) {
        fprintf(stderr, "An option (-c, -s or -e) must be provided\n");
        print_usage();
        return 3;
    }

    bfu_process p = {0};
    bfu_process_run_sync(&p, "bw", "sync");
    i32 res = 0;

    bfu_array_f(bw_item) items = NULL;
    if (!bw_try_unlock()) { 
        bfu_string_f password = {0};
        if (!read_password(&password)) {
            rofi_error("Password not provided! Exiting...\n");
            return 4;
        }


        if (!bw_unlock(password)) {
            rofi_error("Incorrect password. Exiting...\n");
            res = 4; goto end;
        }
    }

    if (mode == MODE_CREATE) {
        bw_item item = {0};
        bfu_string_push(&item.name, arg);
        while (true) {
            i8 res = edit_form(&item);
            if (res == 0) break;
            if (res == 1) { 
                if (item.name.size == 0) {
                    rofi_error("Name is missing!");
                    continue;
                }
                if (item.username.size == 0) {
                    rofi_error("Username is missing!");
                    continue;
                }
                if (item.password.size == 0) {
                    rofi_error("Password is missing!");
                    continue;
                }
                bw_create(item);
                wl_copy(item.password);
                break;
            };
        }
        free_bw_items(&item);
        goto end;
    }

    items = bw_items(arg);
    i32 selected = rofi_items(items);
    if (selected < 0) {
        rofi_error("No item selected. Exiting...\n");
        res = 4; goto end;
    }

    if (mode == MODE_SEARCH) {
        bfu_string_f option = rofi_dmenu("Which item you want to copy?", "username", "password", "totp", NULL);
        if (option.size == 0) {
            rofi_error("No option selected. Exiting...\n");
            res = 4; goto end;
        }
        bfu_string_f item = bw_get(items[selected].id, option);
        if (item.size > 0) {
            wl_copy(item);
        }
        else {
            bfu_string_f err = {0};
            bfu_string_format(&err, "%s not found!", option.data);
            rofi_error(err.data);
            res = 5; goto end;
        }
    }
    else if (mode == MODE_EDIT) {
        bw_item *item = &items[selected];
        while (true) {
            i8 res = edit_form(item);
            if (res == 0) break;
            if (res == 1) { bw_save(*item); break; };
        }
    }

end:
    bfu_string_delete(&session);
    free_bw_items(items);
    return res;
}
