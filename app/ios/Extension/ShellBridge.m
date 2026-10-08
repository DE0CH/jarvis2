// React Native's way to the shell: ask it to enter secure mode (with options that pre-fill its page), ask for
// the router's address + the Access token, ask it to sign in. The shell tells React Native when it has left
// secure mode again (event "secureFinished"). Calls with an answer carry a reply block to HostLink.
#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface ShellBridge : RCTEventEmitter <RCTBridgeModule>
@end

@implementation ShellBridge {
  BOOL _observing;
}
RCT_EXPORT_MODULE();
+ (BOOL)requiresMainQueueSetup { return NO; }
- (NSArray<NSString *> *)supportedEvents { return @[@"secureFinished"]; }

- (instancetype)init
{
  if ((self = [super init])) {
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(shellEvent:) name:@"JarvisShellEvent" object:nil];
  }
  return self;
}
- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }
- (void)startObserving { _observing = YES; }
- (void)stopObserving { _observing = NO; }
- (void)shellEvent:(NSNotification *)n
{
  if (!_observing) return;
  [self sendEventWithName:n.userInfo[@"name"] body:n.userInfo[@"body"]];
}

static void shellCall(NSString *method, NSString *arg, void (^reply)(NSString *))
{
  dispatch_async(dispatch_get_main_queue(), ^{
    NSMutableDictionary *info = [@{@"method": method, @"arg": arg ?: @""} mutableCopy];
    if (reply) info[@"reply"] = [reply copy];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"JarvisShellCall" object:nil userInfo:info];
  });
}

RCT_EXPORT_METHOD(session:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
  shellCall(@"session", @"", ^(NSString *json) { resolve(json); });
}

RCT_EXPORT_METHOD(signIn:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
  shellCall(@"signIn", @"", ^(NSString *token) { resolve(token); });
}

RCT_EXPORT_METHOD(requestSecureMode:(NSString *)options)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    [[NSNotificationCenter defaultCenter] postNotificationName:@"JarvisShellCall" object:nil
                                                      userInfo:@{@"method": @"secure", @"arg": options ?: @"{}"}];
  });
}
@end
