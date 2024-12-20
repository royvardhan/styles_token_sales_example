// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use alloy_primitives::Address;
use alloy_sol_types::sol;
/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{alloy_primitives::U256, block, call::Call, contract, evm, msg, prelude::*};

// Interfaces for the ERC20 contract
sol_interface! {
    interface IERC20 {
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address recipient, uint256 amount)
            external
            returns (bool);
        function allowance(address owner, address spender)
            external
            view
            returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address sender, address recipient, uint256 amount)
            external
            returns (bool);
        function mint(address to, uint256 amount) external returns (bool);
    }
}

sol_storage! {
    #[entrypoint]
    pub struct TokenSales {
        address mock_token_address;
        address usdc_token_address;

        // Admin address
        address admin_address;

        // Static pricing
        uint256 usdc_token_price;

        // This is created so that we can assign tokens to users
        // And it is claimable only when sale is over
        // If transfer is done before sale is over, user can gamify the sale
        mapping(address => uint256) token_to_user;

        // Limit per user
        uint256 max_tokens_per_user;

        // Total tokens sold
        uint256 max_tokens_to_sell;

        // Total tokens sold
        uint256 tokens_sold;
        
        // For evaluation
        uint256 sale_start_time;
        uint256 sale_end_time;
        bool emergency_stop;
    }
}


sol! {
    // Events
    error SaleAlreadyInitialized();
    error NotAdmin();
    error MockTokenSet();
    error UsdcTokenSet();
    error ExternalCallFailed();
    error NotEnoughUsdcBalance();
    error MaxTokensPerUserReached();
    error MaxTokensToSellReached();
    error SaleActive();
    error SaleNotStarted();
    error SaleEnded();
    error EmergencyStop();
    error InvalidTokenAddress();
    error InvalidAmount();
    error InvalidTime();
    error InvalidRecovery();


    // Events
    event TokensPurchased(address indexed buyer, uint256 amount, uint256 cost);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);
    event EmergencyPaused(bool status);
    event TokensRecovered(address token, address to, uint256 amount);
    event SaleExtended(uint256 oldEndTime, uint256 newEndTime);
    event AdminChanged(address oldAdmin, address newAdmin);
    event SaleInitialized(
        address mockToken,
        address usdcToken,
        uint256 price,
        uint256 maxPerUser,
        uint256 maxTotal,
        uint256 startTime,
        uint256 endTime
    );
    event TokensClaimed(address indexed user, uint256 amount);
}

/// Represents the ways methods may fail.
#[derive(SolidityError)]
pub enum TokenSalesError {
    SaleAlreadyInitialized(SaleAlreadyInitialized),
    NotAdmin(NotAdmin),
    MockTokenSet(MockTokenSet),
    UsdcTokenSet(UsdcTokenSet),
    ExternalCallFailed(ExternalCallFailed),
    NotEnoughUsdcBalance(NotEnoughUsdcBalance),
    MaxTokensPerUserReached(MaxTokensPerUserReached),
    MaxTokensToSellReached(MaxTokensToSellReached),
    SaleActive(SaleActive),
    SaleNotStarted(SaleNotStarted),
    SaleEnded(SaleEnded),
    EmergencyStop(EmergencyStop),
    InvalidTokenAddress(InvalidTokenAddress),
    InvalidAmount(InvalidAmount),
    InvalidTime(InvalidTime),
    InvalidRecovery(InvalidRecovery),
}

// Helper, private functions
impl TokenSales {
    fn validate_admin(&self) -> Result<(), TokenSalesError> {
        if msg::sender() != self.admin_address.get() {
            return Err(TokenSalesError::NotAdmin(NotAdmin {}));
        }
        Ok(())
    }

    fn validate_sale_status(&self) -> Result<(), TokenSalesError> {
        if self.emergency_stop.get() {
            return Err(TokenSalesError::EmergencyStop(EmergencyStop {}));
        }

        let current_time = U256::from(block::timestamp());

        if current_time < self.sale_start_time.get() {
            return Err(TokenSalesError::SaleNotStarted(SaleNotStarted {}));
        }

        if current_time > self.sale_end_time.get() {
            return Err(TokenSalesError::SaleEnded(SaleEnded {}));
        }

        Ok(())
    }

    fn validate_sale_over(&self) -> Result<(), TokenSalesError> {
        let current_time = U256::from(block::timestamp());
        if current_time <= self.sale_end_time.get() && !self.emergency_stop.get() {
            return Err(TokenSalesError::SaleActive(SaleActive {}));
        }
        Ok(())
    }

    fn validate_init_params(
        &self,
        mock_token_address: Address,
        usdc_token_address: Address,
        usdc_token_price: U256,
        max_tokens_per_user: U256,
        max_tokens_to_sell: U256,
        admin_address: Address,
        sale_start_time: U256,
        sale_end_time: U256,
    ) -> Result<(), TokenSalesError> {
        // Check if sale is already initialized
        if self.sale_start_time.get() != U256::ZERO {
            return Err(TokenSalesError::SaleAlreadyInitialized(
                SaleAlreadyInitialized {},
            ));
        }

        // Validate token addresses
        if mock_token_address.is_zero() || self.mock_token_address.get() != Address::ZERO {
            return Err(TokenSalesError::MockTokenSet(MockTokenSet {}));
        }

        if usdc_token_address.is_zero() || self.usdc_token_address.get() != Address::ZERO {
            return Err(TokenSalesError::UsdcTokenSet(UsdcTokenSet {}));
        }

        // Validate admin address
        if admin_address.is_zero() {
            return Err(TokenSalesError::InvalidTokenAddress(InvalidTokenAddress {}));
        }

        // Validate amounts
        if usdc_token_price.is_zero()
            || max_tokens_per_user.is_zero()
            || max_tokens_to_sell.is_zero()
        {
            return Err(TokenSalesError::InvalidAmount(InvalidAmount {}));
        }

        // Validate max tokens per user cannot be greater than total tokens to sell
        if max_tokens_per_user > max_tokens_to_sell {
            return Err(TokenSalesError::InvalidAmount(InvalidAmount {}));
        }

        // Validate sale times
        let current_time = U256::from(block::timestamp());
        if sale_start_time <= current_time {
            return Err(TokenSalesError::InvalidTime(InvalidTime {}));
        }

        if sale_end_time <= sale_start_time {
            return Err(TokenSalesError::InvalidTime(InvalidTime {}));
        }

        Ok(())
    }
}

#[public]
impl TokenSales {
    // Init
    pub fn initialize(
        &mut self,
        mock_token_address: Address,
        usdc_token_address: Address,
        usdc_token_price: U256,
        max_tokens_per_user: U256,
        max_tokens_to_sell: U256,
        admin_address: Address,
        sale_start_time: U256,
        sale_end_time: U256,
    ) -> Result<(), TokenSalesError> {
        self.validate_init_params(
            mock_token_address,
            usdc_token_address,
            usdc_token_price,
            max_tokens_per_user,
            max_tokens_to_sell,
            admin_address,
            sale_start_time,
            sale_end_time,
        )?;

        self.mock_token_address.set(mock_token_address);
        self.usdc_token_address.set(usdc_token_address);
        self.usdc_token_price.set(usdc_token_price);
        self.max_tokens_per_user.set(max_tokens_per_user);
        self.max_tokens_to_sell.set(max_tokens_to_sell);
        self.admin_address.set(admin_address);
        self.sale_start_time.set(sale_start_time);
        self.sale_end_time.set(sale_end_time);

        evm::log(SaleInitialized {
            mockToken: mock_token_address,
            usdcToken: usdc_token_address,
            price: usdc_token_price,
            maxPerUser: max_tokens_per_user,
            maxTotal: max_tokens_to_sell,
            startTime: sale_start_time,
            endTime: sale_end_time,
        });

        Ok(())
    }

    // User functions
    fn buy_mock_token(&mut self, amount: U256) -> Result<(), TokenSalesError> {
        self.validate_sale_status()?;

        // Check for max_tokens_to_sell
        if self.tokens_sold.get() + amount > self.max_tokens_to_sell.get() {
            return Err(TokenSalesError::MaxTokensToSellReached(
                MaxTokensToSellReached {},
            ));
        }

        // Before doing anything, check if the user has already bought the maximum amount of tokens
        let max_tokens_per_user = self.max_tokens_per_user.get();
        let sender = msg::sender();
        let mock_token_balance = self.token_to_user.get(sender);

        if mock_token_balance + amount > max_tokens_per_user {
            return Err(TokenSalesError::MaxTokensPerUserReached(
                MaxTokensPerUserReached {},
            ));
        }

        // Calculate the expected amount of USDC tokens
        let price = self.usdc_token_price.get();
        let expected_amount = price * amount;

        // Check if the user has enough USDC tokens
        let usdc_token_address = self.usdc_token_address.get();
        let usdc_token = IERC20::new(usdc_token_address);

        let config = Call::new();
        let usdc_balance = usdc_token
            .balance_of(config, sender)
            .map_err(|_e| TokenSalesError::ExternalCallFailed(ExternalCallFailed {}))?;

        if usdc_balance < expected_amount {
            return Err(TokenSalesError::NotEnoughUsdcBalance(
                NotEnoughUsdcBalance {},
            ));
        }

        // Transfer the USDC tokens to the contract
        let config = Call::new();

        usdc_token
            .transfer_from(config, sender, contract::address(), expected_amount)
            .map_err(|_e| TokenSalesError::ExternalCallFailed(ExternalCallFailed {}))?;

        // Assign tokens to user
        self.token_to_user
            .insert(sender, mock_token_balance + amount);

        // Update the total tokens sold
        self.tokens_sold.set(self.tokens_sold.get() + amount);

        // After successful purchase, emit event
        evm::log(TokensPurchased {
            buyer: sender,
            amount,
            cost: expected_amount,
        });

        Ok(())
    }
     
    // Can claim when the sale is over
    pub fn claim_tokens(&mut self) -> Result<(), TokenSalesError> {
        self.validate_sale_over()?;
        let sender = msg::sender();
        let amount = self.token_to_user.get(sender);
        self.token_to_user.insert(sender, U256::ZERO);

        let mock_token = IERC20::new(self.mock_token_address.get());
        let config = Call::new();
        mock_token
            .mint(config, sender, amount)
            .map_err(|_e| TokenSalesError::ExternalCallFailed(ExternalCallFailed {}))?;

        evm::log(TokensClaimed {
            user: sender,
            amount,
        });

        Ok(())
    }

    // Admin functions
    pub fn set_new_price(&mut self, new_price: U256) -> Result<(), TokenSalesError> {
        self.validate_admin()?;
        let old_price = self.usdc_token_price.get();
        self.usdc_token_price.set(new_price);
        evm::log(PriceUpdated {
            oldPrice: old_price,
            newPrice: new_price,
        });
        Ok(())
    }

    pub fn withdraw_usdc(&mut self, amount: U256) -> Result<(), TokenSalesError> {
        self.validate_admin()?;
        let usdc_token = IERC20::new(self.usdc_token_address.get());
        let config = Call::new();

        usdc_token
            .transfer(config, msg::sender(), amount)
            .map_err(|_e| TokenSalesError::ExternalCallFailed(ExternalCallFailed {}))?;

        Ok(())
    }

    pub fn emergency_pause(&mut self, status: bool) -> Result<(), TokenSalesError> {
        self.validate_admin()?;
        self.emergency_stop.set(status);
        evm::log(EmergencyPaused { status });
        Ok(())
    }

    pub fn recover_tokens(
        &mut self,
        token_address: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), TokenSalesError> {
        self.validate_admin()?;

        if token_address.is_zero() || to.is_zero() || amount.is_zero() {
            return Err(TokenSalesError::InvalidRecovery(InvalidRecovery {}));
        }

        let token = IERC20::new(token_address);
        let config = Call::new();

        token
            .transfer(config, to, amount)
            .map_err(|_e| TokenSalesError::ExternalCallFailed(ExternalCallFailed {}))?;

        evm::log(TokensRecovered {
            token: token_address,
            to,
            amount,
        });

        Ok(())
    }

    pub fn change_admin(&mut self, new_admin: Address) -> Result<(), TokenSalesError> {
        self.validate_admin()?;
        let old_admin = self.admin_address.get();
        self.admin_address.set(new_admin);

        evm::log(AdminChanged {
            oldAdmin: old_admin,
            newAdmin: new_admin,
        });

        Ok(())
    }
    pub fn extend_sale(&mut self, new_end_time: U256) -> Result<(), TokenSalesError> {
        self.validate_admin()?;

        let current_end_time = self.sale_end_time.get();
        let current_time = U256::from(block::timestamp());

        // Cannot extend if sale has already ended
        if current_time > current_end_time {
            return Err(TokenSalesError::SaleEnded(SaleEnded {}));
        }

        // New end time must be after current end time
        if new_end_time <= current_end_time {
            return Err(TokenSalesError::InvalidTime(InvalidTime {}));
        }

        self.sale_end_time.set(new_end_time);

        // Emit event for sale extension
        evm::log(SaleExtended {
            oldEndTime: current_end_time,
            newEndTime: new_end_time,
        });

        Ok(())
    }

    pub fn update_user_tokens(
        &mut self,
        user: Address,
        amount: U256,
    ) -> Result<(), TokenSalesError> {
        self.validate_admin()?;
        self.token_to_user.insert(user, amount);
        Ok(())
    }

    // Getters
    pub fn get_price(&self) -> Result<U256, TokenSalesError> {
        Ok(self.usdc_token_price.get())
    }

    pub fn get_tokens_sold(&self) -> Result<U256, TokenSalesError> {
        Ok(self.tokens_sold.get())
    }

    pub fn get_max_tokens_per_user(&self) -> Result<U256, TokenSalesError> {
        Ok(self.max_tokens_per_user.get())
    }

    pub fn get_max_tokens_to_sell(&self) -> Result<U256, TokenSalesError> {
        Ok(self.max_tokens_to_sell.get())
    }

    pub fn get_sale_start_time(&self) -> Result<U256, TokenSalesError> {
        Ok(self.sale_start_time.get())
    }

    pub fn get_sale_end_time(&self) -> Result<U256, TokenSalesError> {
        Ok(self.sale_end_time.get())
    }

    pub fn get_admin_address(&self) -> Result<Address, TokenSalesError> {
        Ok(self.admin_address.get())
    }

    pub fn get_mock_token_address(&self) -> Result<Address, TokenSalesError> {
        Ok(self.mock_token_address.get())
    }

    pub fn get_usdc_token_address(&self) -> Result<Address, TokenSalesError> {
        Ok(self.usdc_token_address.get())
    }

    pub fn get_emergency_stop(&self) -> Result<bool, TokenSalesError> {
        Ok(self.emergency_stop.get())
    }

    pub fn get_token_to_user(&self, user: Address) -> Result<U256, TokenSalesError> {
        Ok(self.token_to_user.get(user))
    }
}
