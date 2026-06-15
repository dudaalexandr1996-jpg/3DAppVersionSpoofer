#include "Tweak.h"
#import <sys/sysctl.h>
#import <dlfcn.h>

// Hook sysctl для приховування jailbreak
typedef int (*sysctl_t)(int *, u_int, void *, size_t *, void *, size_t);
static sysctl_t orig_sysctl = NULL;

int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
	int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
	
	// Приховуємо jailbreak маркери в sysctl результатах
	if (oldp && oldlenp && result == 0) {
		char *str = (char *)oldp;
		if (strstr(str, "jailbreak") || strstr(str, "/var/jb") || strstr(str, "dyld")) {
			memset(oldp, 0, *oldlenp);
			*oldlenp = 0;
			return -1; // Error
		}
	}
	
	return result;
}

// Hook stat для приховування /var/jb
typedef int (*stat_t)(const char *, struct stat *);
static stat_t orig_stat = NULL;

int hooked_stat(const char *path, struct stat *sb) {
	if (path && (strstr(path, "/var/jb") || strstr(path, "cydia"))) {
		errno = ENOENT;
		return -1;
	}
	return orig_stat(path, sb);
}

// Hook fork для приховування fork ability
extern int fork(void);
int hooked_fork(void) {
	return -1; // Вернути помилку
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if ([path containsString:@"/var/jb"] || 
	    [path containsString:@"cydia"] || 
	    [path containsString:@"frida"] ||
	    [path containsString:@"TrollStore"]) {
		return NO;
	}
	return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
	if ([path containsString:@"/var/jb"] || 
	    [path containsString:@"cydia"]) {
		return NO;
	}
	return %orig;
}
%end

%hook NSProcessInfo
- (NSDictionary *)environment {
	NSMutableDictionary *env = [[%orig mutableCopy] autorelease];
	[env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
	[env removeObjectForKey:@"FRIDA_SERVER"];
	return env;
}
%end

%ctor {
	// Підмінюємо системні функції
	orig_sysctl = (sysctl_t)dlsym(RTLD_NEXT, "sysctl");
	orig_stat = (stat_t)dlsym(RTLD_NEXT, "stat");
	
	if (orig_sysctl) {
		MSHookFunction((void *)orig_sysctl, (void *)hooked_sysctl, (void **)&orig_sysctl);
	}
	if (orig_stat) {
		MSHookFunction((void *)orig_stat, (void *)hooked_stat, (void **)&orig_stat);
	}
}
