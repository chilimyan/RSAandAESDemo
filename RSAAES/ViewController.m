//
//  ViewController.m
//  RSAAES
//
//  Created by Apple on 2017/4/7.
//  Copyright © 2017年 chilim. All rights reserved.
//

#import "ViewController.h"
#import "CRSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [[CRSA shareInstance] rsa_aes];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
