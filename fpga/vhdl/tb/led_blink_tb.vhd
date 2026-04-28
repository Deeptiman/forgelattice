library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity led_blink_tb is
end led_blink_tb;

architecture behave of led_blink_tb is

    -- 25 MHz = 40 nanoseconds period
    constant c_CLOCK_PERIOD : time := 40 ns;

    signal r_CLOCK : std_logic := '0';
    signal r_ENABLE : std_logic := '0';
    signal r_SWITCH_1 : std_logic := '0';
    signal r_SWITCH_2 : std_logic := '0';
    signal w_LED_DRIVE : std_logic;

    -- Component declaration for the Unit Under Test (UUT)
    component led_blink is
        port (
            i_clock : in std_logic;
            i_enable : in std_logic;
            i_switch_1 : in std_logic;
            i_switch_2 : in std_logic;
            o_led_drive : out std_logic
        );
    end component led_blink;

begin

   -- Instantiate the Unit Under Test (UUT)
   UUT: led_blink
    port map (
        i_clock => r_CLOCK,
        i_enable => r_ENABLE,
        i_switch_1 => r_SWITCH_1,
        i_switch_2 => r_SWITCH_2,
        o_led_drive => w_LED_DRIVE
    );

   p_CLK_GEN : process is
   begin
    wait for c_CLOCK_PERIOD/2;
    r_CLOCK <= not r_CLOCK;
   end process p_CLK_GEN;

   process
   begin
        r_ENABLE <= '1';

        r_SWITCH_1 <= '0';
        r_SWITCH_2 <= '0';
        wait for 0.2 sec;

        r_SWITCH_1 <= '0';
        r_SWITCH_2 <= '1';
        wait for 0.2 sec;

        r_SWITCH_1 <= '1';
        r_SWITCH_2 <= '0';
        wait for 0.5 sec;

        r_SWITCH_1 <= '1';
        r_SWITCH_2 <= '1';
        wait for 0.2 sec;

   end process;

end behave;