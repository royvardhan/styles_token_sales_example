# TokenSales Smart Contract

A Stylus smart contract for managing token sales with USDC as the payment token. This contract implements a time-bound token sale with various safety features and administrative controls.

## Features

- Time-bounded sale period
- USDC payment integration
- Per-user purchase limits
- Total sale cap
- Delayed token claiming mechanism
- Emergency pause functionality
- Administrative controls

## Core Functions

### User Functions

- `buy_mock_token(amount)`: Purchase tokens during the active sale period
- `claim_tokens()`: Claim purchased tokens after the sale ends

### Admin Functions

- `initialize(...)`: Set up the sale with initial parameters
- `set_new_price(new_price)`: Update the token price
- `withdraw_usdc(amount)`: Withdraw collected USDC
- `emergency_pause(status)`: Pause/unpause the sale
- `recover_tokens(token_address, to, amount)`: Recover any ERC20 tokens
- `change_admin(new_admin)`: Transfer admin rights
- `extend_sale(new_end_time)`: Extend the sale duration
- `update_user_tokens(user, amount)`: Update user token allocation

### View Functions

- `get_price()`: Current token price
- `get_tokens_sold()`: Total tokens sold
- `get_max_tokens_per_user()`: Maximum tokens per user
- `get_max_tokens_to_sell()`: Total tokens available for sale
- `get_sale_start_time()`: Sale start timestamp
- `get_sale_end_time()`: Sale end timestamp
- `get_admin_address()`: Current admin address
- `get_mock_token_address()`: Mock token contract address
- `get_usdc_token_address()`: USDC token contract address
- `get_emergency_stop()`: Emergency pause status
- `get_token_to_user(user)`: User's token allocation

## Safety Features

1. Time-bound sale period
2. Emergency pause mechanism
3. Purchase limits per user
4. Total sale cap
5. Delayed token claiming
6. Admin-only controls
7. Input validation
8. Token recovery function

## Events

- `TokensPurchased`: Emitted when tokens are purchased
- `PriceUpdated`: Emitted when token price is updated
- `EmergencyPaused`: Emitted when sale is paused/unpaused
- `TokensRecovered`: Emitted when tokens are recovered
- `SaleExtended`: Emitted when sale duration is extended
- `AdminChanged`: Emitted when admin is changed
- `SaleInitialized`: Emitted when sale is initialized
- `TokensClaimed`: Emitted when tokens are claimed

## Error Handling

The contract includes comprehensive error handling for various scenarios:
- Sale state validation
- Administrative access control
- Token transfer failures
- Balance checks
- Time-based restrictions
- Input validation

## Usage

1. Deploy the contract
2. Initialize the sale with required parameters
3. Users can purchase tokens during the active sale period
4. Users claim their tokens after the sale ends
5. Admin can manage the sale parameters and emergency controls

## Security Considerations

- Tokens are only claimable after the sale ends to prevent gaming
- Admin functions are protected with access control
- Emergency pause available for unexpected situations
- All external calls are checked for success
