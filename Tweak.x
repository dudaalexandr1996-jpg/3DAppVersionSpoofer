#include "Tweak.h"
#import <sys/sysctl.h>

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
	NSMutableDictionary *env = [[%orig mutableCopy] copy];
	[env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
	return env;
}
%end

%ctor {
}
