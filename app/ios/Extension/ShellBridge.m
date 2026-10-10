// React Native's way to the shell: ask it to enter secure mode (with options that pre-fill its page), ask for
// the router's address + the Access token, ask it to sign in. The shell tells React Native when it has left
// secure mode again (event "secureFinished"), and React Native answers once it has drawn the result (secureSettled). Calls with an answer carry a reply block to HostLink.
#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface ShellBridge : RCTEventEmitter <RCTBridgeModule>
@end

// The shell's events ("secureFinished") can arrive before React Native has loaded this module (Done on the Reset
// or recover page at first launch, while the bundle is still starting): they wait here from the moment the
// extension's code loads and go out once JavaScript listens.
static NSMutableArray<NSDictionary *> *pendingEvents;
static __weak ShellBridge *liveBridge;

@interface ShellBridge () { @public BOOL _observing; }
@end

// at image load (RCT_EXPORT_MODULE owns +load)
__attribute__((constructor)) static void ShellBridgeQueueEvents(void)
{
  pendingEvents = [NSMutableArray new];
  [[NSNotificationCenter defaultCenter] addObserverForName:@"JarvisShellEvent" object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
    ShellBridge *b = liveBridge;
    if (b && b->_observing) [b sendEventWithName:n.userInfo[@"name"] body:n.userInfo[@"body"]];
    else if (n.userInfo) [pendingEvents addObject:n.userInfo];
  }];
}

@implementation ShellBridge
RCT_EXPORT_MODULE();
+ (BOOL)requiresMainQueueSetup { return NO; }
- (NSArray<NSString *> *)supportedEvents { return @[@"secureFinished"]; }

- (void)startObserving
{
  dispatch_async(dispatch_get_main_queue(), ^{
    self->_observing = YES;
    liveBridge = self;
    NSArray<NSDictionary *> *q = [pendingEvents copy];
    [pendingEvents removeAllObjects];
    for (NSDictionary *e in q) [self sendEventWithName:e[@"name"] body:e[@"body"]];
  });
}
- (void)stopObserving { dispatch_async(dispatch_get_main_queue(), ^{ self->_observing = NO; }); }

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

// plain text to the clipboard, written by the shell (lib/clipboard.native.ts)
RCT_EXPORT_METHOD(copyText:(NSString *)text)
{
  shellCall(@"copy", text ?: @"", nil);
}

// React Native has handled the shell's "secureFinished" and drawn the result: the shell may now show the app
RCT_EXPORT_METHOD(secureSettled:(NSString *)requestId)
{
  shellCall(@"settled", requestId ?: @"", nil);
}

RCT_EXPORT_METHOD(requestSecureMode:(NSString *)options)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    [[NSNotificationCenter defaultCenter] postNotificationName:@"JarvisShellCall" object:nil
                                                      userInfo:@{@"method": @"secure", @"arg": options ?: @"{}"}];
  });
}
@end
