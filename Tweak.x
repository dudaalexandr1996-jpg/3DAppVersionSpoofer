#include "Tweak.h"

BOOL isTweakEnabled = YES;

// JAILBREAK DETECTION BYPASS
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if ([path containsString:@"/var/jb"] || [path containsString:@"cydia"] || [path containsString:@"frida"]) {
		return NO;
	}
	return %orig;
}
%end

%hook NSBundle
-(NSDictionary *)infoDictionary {
	NSDictionary *dictionary = %orig;
	NSMutableDictionary *moddedDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionary];
	
	if (!self || ![self isLoaded] || ![[self bundleURL].absoluteString containsString:@"Application"] || !isTweakEnabled) {
		return %orig;
	}
	
	return moddedDictionary;
}
%end

%hook UIDevice
- (id)systemVersion {
	return %orig;
}
%end

%ctor {
	isTweakEnabled = YES;
}
